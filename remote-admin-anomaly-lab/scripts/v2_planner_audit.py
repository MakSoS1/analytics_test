#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.v2_scenarios import (
    V2_BENIGN_FAMILIES,
    V2_SUSPICIOUS_FAMILIES,
    build_v2_semantic_plan,
    summarize_v2_plan,
)
from adminlab.wire_controls import materialize_wire_controls


def load_runner_module():
    path = ROOT / "scripts/run_scenarios_extended_v2.py"
    spec = importlib.util.spec_from_file_location("adminlab_v2_wire_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=2026081402)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--counterfactual-fraction", type=float, default=0.30)
    args = parser.parse_args()

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
    selected = organize_campaign_sequences(selected, bundle["campaigns"], seed=args.seed)
    selected = build_v2_semantic_plan(
        selected,
        seed=args.seed,
        min_counterfactual_fraction=args.counterfactual_fraction,
    )
    selected = materialize_implementation_variants(selected, stage="H", seed=args.seed)
    selected = materialize_wire_controls(selected, bundle["behavior"], seed=args.seed)

    report = summarize_v2_plan(selected)
    protocol_counts = Counter(row.protocol for row in selected)
    label_counts = Counter(int(row.label_binary) for row in selected)
    family_counts = Counter(row.campaign_type for row in selected)
    benign_families = sorted({name for name in family_counts if name in V2_BENIGN_FAMILIES})
    suspicious_families = sorted({name for name in family_counts if name in V2_SUSPICIOUS_FAMILIES})
    per_protocol_labels = {
        protocol: {
            str(label): sum(1 for row in selected if row.protocol == protocol and int(row.label_binary) == label)
            for label in (0, 1)
        }
        for protocol in runner.TRAIN_PROTOCOLS
    }

    failures: list[str] = []
    if len(selected) != args.count:
        failures.append("row_count")
    if abs(label_counts[0] - label_counts[1]) > max(2, int(args.count * 0.02)):
        failures.append("label_balance")
    expected_protocol = args.count // len(runner.TRAIN_PROTOCOLS)
    if any(abs(protocol_counts[p] - expected_protocol) > 1 for p in runner.TRAIN_PROTOCOLS):
        failures.append("protocol_balance")
    if any(min(counts.values()) == 0 for counts in per_protocol_labels.values()):
        failures.append("protocol_label_coverage")
    if min(report["timeline_days_by_protocol"].values(), default=0) < 30:
        failures.append("timeline_coverage")
    if float(report["counterfactual_pair_fraction"]) + 1e-12 < args.counterfactual_fraction:
        failures.append("counterfactual_coverage")
    if report["invalid_counterfactual_pairs"]:
        failures.append("invalid_counterfactual_pair")
    if len(benign_families) < 6:
        failures.append("benign_family_diversity")
    if len(suspicious_families) < 6:
        failures.append("suspicious_family_diversity")

    output = {
        "schema_version": 2,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "seed": args.seed,
        "requested": args.count,
        "planned_pool_rows": len(planned),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "label_counts": {str(k): v for k, v in sorted(label_counts.items())},
        "per_protocol_label_counts": per_protocol_labels,
        "benign_families": benign_families,
        "suspicious_families": suspicious_families,
        "family_counts": dict(sorted(family_counts.items())),
        "semantic_report": report,
        "requirements": {
            "counterfactual_pair_fraction_min": args.counterfactual_fraction,
            "timeline_days_per_protocol_min": 30,
            "semantic_families_per_class_min": 6,
            "label_delta_fraction_max": 0.02,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    if failures:
        raise SystemExit("V2 planner audit failed: " + ",".join(failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
