#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.manifest import SessionRecord, write_sessions
from adminlab.v3_campaigns import audit_v3_campaigns, organize_v3_campaigns
from adminlab.v3_causal import build_v3_causal_plan
from adminlab.v3_signal import audit_v3_signal_plan
from adminlab.wire_controls import materialize_wire_controls


def _load_legacy_runner():
    path = ROOT / "scripts/run_scenarios_extended_v2.py"
    spec = importlib.util.spec_from_file_location("adminlab_v3_legacy_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _required_source_identities(count: int) -> int:
    return 32 if count >= 1000 else min(20, max(4, count // 2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=["H"])
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--core-state", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--v3-matched-fraction", type=float, default=0.40)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("V3 causal scenario runner requires root")

    legacy = _load_legacy_runner()
    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    namespaces = legacy.namespace_map(topology)

    pool = plan_digital_twin_sessions(
        topology,
        scenarios,
        netem,
        bundle,
        seed=args.seed,
        count=max(args.count * 16, args.count + 1600),
        stage="H",
    )
    selected = legacy.balanced_select(pool, args.count, legacy.TRAIN_PROTOCOLS)
    selected = build_v3_causal_plan(
        selected,
        topology=topology,
        seed=args.seed,
        matched_fraction=args.v3_matched_fraction,
    )
    selected = organize_v3_campaigns(selected, seed=args.seed)
    selected = materialize_implementation_variants(selected, stage="H", seed=args.seed)
    selected = materialize_wire_controls(selected, bundle["behavior"], seed=args.seed)

    signal = audit_v3_signal_plan(selected)
    causal = signal["causal_observability"]
    source_count = len({row.src_host_id for row in selected})
    source_required = _required_source_identities(args.count)
    if float(signal["counterfactual_row_fraction"]) + 1e-12 < args.v3_matched_fraction:
        raise RuntimeError(f"V3 counterfactual coverage below target: {signal}")
    if float(signal["matched_hour_pair_fraction"]) < 0.80:
        raise RuntimeError(f"V3 current-session time matching below target: {signal}")
    if signal["invalid_counterfactual_pairs"]:
        raise RuntimeError(f"invalid V3 counterfactual pairs: {signal['invalid_counterfactual_pairs']}")
    if not causal["valid"]:
        raise RuntimeError(f"V3 causal observability failed: {causal}")
    if source_count < source_required:
        raise RuntimeError(f"V3 source diversity below gate: {source_count} < {source_required}")

    args.out.mkdir(parents=True, exist_ok=True)
    fixtures = args.out / "inert-fixtures"
    fixtures.mkdir(exist_ok=True)
    write_sessions(selected, args.out / "sessions-planned.jsonl")
    executed = [legacy.execute(row, namespaces, args.core_state, fixtures, netem) for row in selected]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    status_counts = Counter("success" if row.status == "success" else "failed" for row in executed)
    protocol_counts = Counter(row.protocol for row in executed)
    label_counts = Counter("suspicious" if row.label_binary else "benign" for row in executed)
    implementation_counts = Counter(row.implementation_id for row in executed)
    family_counts = Counter(row.campaign_type for row in executed)
    source_role_counts = Counter(row.src_role for row in executed)
    failures = [row.to_dict() for row in executed if row.status != "success"]
    campaigns: dict[str, list[SessionRecord]] = defaultdict(list)
    for row in selected:
        campaigns[row.campaign_id].append(row)

    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(status_counts),
        "protocol_counts": dict(protocol_counts),
        "label_counts": dict(label_counts),
        "implementation_counts": dict(implementation_counts),
        "family_counts": dict(family_counts),
        "source_identity_count": source_count,
        "source_identity_required": source_required,
        "source_role_counts": dict(source_role_counts),
        "protocol_balance_max_minus_min": max(protocol_counts.values()) - min(protocol_counts.values()),
        "campaign_count": len(campaigns),
        "multi_session_campaigns": sum(1 for rows in campaigns.values() if len(rows) >= 3),
        "multi_protocol_campaigns": sum(1 for rows in campaigns.values() if len({row.protocol for row in rows}) >= 2),
        "train_protocols": list(legacy.TRAIN_PROTOCOLS),
        "planner": "digital_twin_v3_causal",
        "label_assignment_policy": "observable_baseline_or_mutation_then_label",
        "wire_controls_label_dependent": False,
        "implementation_choice_label_dependent": False,
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "v3_signal": signal,
        "v3_campaigns": audit_v3_campaigns(selected),
        "failures": failures[:20],
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))

    if failures:
        return 1
    if status_counts.get("success", 0) != args.count:
        return 1
    if label_counts != Counter({"benign": args.count // 2, "suspicious": args.count // 2}):
        return 1
    if set(protocol_counts) != set(legacy.TRAIN_PROTOCOLS) or summary["protocol_balance_max_minus_min"] > 1:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
