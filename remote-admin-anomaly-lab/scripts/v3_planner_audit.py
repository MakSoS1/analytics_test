#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.v2_scenarios import V2_BENIGN_FAMILIES, V2_SUSPICIOUS_FAMILIES
from adminlab.v3_campaigns import audit_v3_campaigns, organize_v3_campaigns
from adminlab.v3_signal import audit_v3_signal_plan, build_v3_signal_plan
from adminlab.v3_splits import assign_grouped_splits_v3
from adminlab.wire_controls import materialize_wire_controls


def load_runner_module():
    path = ROOT / "scripts/run_scenarios_extended_v2.py"
    spec = importlib.util.spec_from_file_location("adminlab_v3_wire_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _timeline_days(rows, protocol: str) -> int:
    values = {int(row.simulated_day) for row in rows if row.protocol == protocol}
    return len(values)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=2026081403)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/v3_research.yaml")
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    runner = load_runner_module()
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")

    planned = plan_digital_twin_sessions(
        topology,
        scenarios,
        netem,
        bundle,
        seed=args.seed,
        count=max(args.count * 16, args.count + 1600),
        stage="H",
    )
    selected = runner.balanced_select(planned, args.count, runner.TRAIN_PROTOCOLS)
    selected = build_v3_signal_plan(
        selected,
        seed=args.seed,
        matched_fraction=float(cfg["matched_counterfactual_fraction"]),
    )
    selected = organize_v3_campaigns(selected, seed=args.seed)
    selected = materialize_implementation_variants(selected, stage="H", seed=args.seed)
    selected = materialize_wire_controls(selected, bundle["behavior"], seed=args.seed)

    signal = audit_v3_signal_plan(selected)
    campaigns = audit_v3_campaigns(selected)
    protocol_counts = Counter(row.protocol for row in selected)
    label_counts = Counter(int(row.label_binary) for row in selected)
    family_counts = Counter(str(row.campaign_type) for row in selected)
    benign_families = sorted({name for name in family_counts if name in V2_BENIGN_FAMILIES})
    suspicious_families = sorted({name for name in family_counts if name in V2_SUSPICIOUS_FAMILIES})
    per_protocol_labels = {
        protocol: {
            str(label): sum(1 for row in selected if row.protocol == protocol and int(row.label_binary) == label)
            for label in (0, 1)
        }
        for protocol in runner.TRAIN_PROTOCOLS
    }
    timeline = {protocol: _timeline_days(selected, protocol) for protocol in runner.TRAIN_PROTOCOLS}

    split_frame = pd.DataFrame([row.to_dict() for row in selected])
    splits, split_report = assign_grouped_splits_v3(split_frame, seed=args.seed)
    split_counts = split_report["split_counts"]
    total_split = sum(split_counts.values())
    challenge_fraction = split_counts.get("challenge", 0) / total_split if total_split else 0.0

    failures: list[str] = []
    if len(selected) != args.count:
        failures.append("row_count")
    if label_counts != Counter({0: args.count // 2, 1: args.count // 2}):
        failures.append("label_balance")
    expected_protocol = args.count // len(runner.TRAIN_PROTOCOLS)
    if any(protocol_counts[protocol] != expected_protocol for protocol in runner.TRAIN_PROTOCOLS):
        failures.append("protocol_balance")
    if any(counts != {"0": expected_protocol // 2, "1": expected_protocol // 2} for counts in per_protocol_labels.values()):
        failures.append("protocol_label_balance")
    if min(timeline.values(), default=0) < 30:
        failures.append("timeline_coverage")
    if float(signal["counterfactual_row_fraction"]) + 1e-12 < float(cfg["matched_counterfactual_fraction"]):
        failures.append("counterfactual_coverage")
    if float(signal["matched_hour_pair_fraction"]) + 1e-12 < float(cfg["min_matched_hour_pair_fraction"]):
        failures.append("matched_hour_pair_fraction")
    if float(signal["max_hour_label_fraction_gap"]) > float(cfg["max_hour_label_fraction_gap"]) + 1e-12:
        failures.append("hour_label_gap")
    if signal["invalid_counterfactual_pairs"]:
        failures.append("invalid_counterfactual_pairs")
    if campaigns["campaign_count"] < int(cfg["min_campaign_groups"]):
        failures.append("campaign_count")
    if campaigns["max_campaign_fraction"] > float(cfg["max_campaign_fraction"]):
        failures.append("campaign_fraction")
    if campaigns["benign_campaign_count"] < 60 or campaigns["suspicious_campaign_count"] < 60:
        failures.append("campaign_label_diversity")
    if campaigns["multi_protocol_campaign_count"] < 30:
        failures.append("multi_protocol_campaigns")
    if len(benign_families) < 6:
        failures.append("benign_family_diversity")
    if len(suspicious_families) < 6:
        failures.append("suspicious_family_diversity")
    if split_counts.get("validation", 0) < int(cfg["min_validation_sessions"]):
        failures.append("validation_size")
    if split_counts.get("test", 0) < int(cfg["min_test_sessions"]):
        failures.append("test_size")
    if not float(cfg["challenge_fraction_min"]) <= challenge_fraction <= float(cfg["challenge_fraction_max"]):
        failures.append("challenge_fraction")

    merged = split_frame[["session_id", "protocol", "label_binary"]].merge(
        splits[["session_id", "split"]], on="session_id", validate="one_to_one"
    )
    for split in ("train", "validation", "test"):
        part = merged[merged["split"] == split]
        if part.empty or set(part["label_binary"].astype(int)) != {0, 1}:
            failures.append(f"{split}_class_coverage")
        if split in ("validation", "test") and set(part["protocol"].astype(str)) != set(runner.TRAIN_PROTOCOLS):
            failures.append(f"{split}_protocol_coverage")

    output = {
        "schema_version": 3,
        "status": "PASS" if not failures else "FAIL",
        "failures": list(dict.fromkeys(failures)),
        "seed": args.seed,
        "requested": args.count,
        "planned_pool_rows": len(planned),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "label_counts": {str(key): int(value) for key, value in sorted(label_counts.items())},
        "per_protocol_label_counts": per_protocol_labels,
        "timeline_days_by_protocol": timeline,
        "benign_families": benign_families,
        "suspicious_families": suspicious_families,
        "family_counts": dict(sorted(family_counts.items())),
        "signal": signal,
        "campaigns": campaigns,
        "splits": split_report,
        "requirements": {
            "matched_fraction_min": float(cfg["matched_counterfactual_fraction"]),
            "matched_hour_pair_fraction_min": float(cfg["min_matched_hour_pair_fraction"]),
            "max_hour_label_fraction_gap": float(cfg["max_hour_label_fraction_gap"]),
            "campaign_groups_min": int(cfg["min_campaign_groups"]),
            "validation_sessions_min": int(cfg["min_validation_sessions"]),
            "test_sessions_min": int(cfg["min_test_sessions"]),
            "challenge_fraction_range": [float(cfg["challenge_fraction_min"]), float(cfg["challenge_fraction_max"])],
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    if failures:
        raise SystemExit("V3 planner audit failed: " + ",".join(output["failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
