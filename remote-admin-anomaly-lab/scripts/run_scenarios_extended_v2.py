#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.extended_wire_v2 import run_rdp_session, run_vnc_session, run_winrm_session
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.manifest import SessionRecord, write_sessions
from adminlab.v2_scenarios import build_v2_semantic_plan, summarize_v2_plan
from adminlab.v3_signal import audit_v3_signal_plan, build_v3_signal_plan
from adminlab.wire_controls import materialize_wire_controls

spec = importlib.util.spec_from_file_location("adminlab_core_wire", ROOT / "scripts/run_scenarios.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load core wire runner")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

LAB_NETWORK = ip_network("10.77.0.0/24")
TRAIN_PROTOCOLS = ("ssh", "smb", "rdp", "vnc")
CHALLENGE_PROTOCOLS = TRAIN_PROTOCOLS + ("winrm",)


def namespace_map(topology: dict) -> dict[str, str]:
    return {str(h["id"]): str(h["namespace"]) for h in topology["hosts"]}


def assert_lab(value: str) -> None:
    if ip_address(value) not in LAB_NETWORK:
        raise RuntimeError(f"non-lab address rejected: {value}")


def _evenly_spaced(records: list[SessionRecord], need: int) -> list[SessionRecord]:
    ordered = sorted(records, key=lambda record: (record.start_ts, record.session_id))
    if need <= 0:
        return []
    if len(ordered) < need:
        raise RuntimeError(f"cannot select {need} rows from a bucket of {len(ordered)}")
    if need == len(ordered):
        return ordered
    if need == 1:
        return [ordered[len(ordered) // 2]]
    indices = [round(index * (len(ordered) - 1) / (need - 1)) for index in range(need)]
    if len(set(indices)) != need:
        raise AssertionError((len(ordered), need, indices))
    return [ordered[index] for index in indices]


def _label_quotas(records: list[SessionRecord], need: int, suspicious_fraction: float) -> tuple[int, int]:
    benign = sum(1 for record in records if int(record.label_binary) == 0)
    suspicious = sum(1 for record in records if int(record.label_binary) == 1)
    target_suspicious = int(round(need * suspicious_fraction))
    target_suspicious = min(target_suspicious, suspicious)
    target_benign = need - target_suspicious
    if target_benign > benign:
        shift = target_benign - benign
        target_benign = benign
        target_suspicious += shift
    if target_suspicious > suspicious:
        shift = target_suspicious - suspicious
        target_suspicious = suspicious
        target_benign += shift
    if target_benign + target_suspicious != need:
        raise RuntimeError(
            f"cannot satisfy binary label quota: need={need} benign={benign} suspicious={suspicious}"
        )
    return target_benign, target_suspicious


def balanced_select(records: list[SessionRecord], count: int, protocols: tuple[str, ...]) -> list[SessionRecord]:
    """Select an equal protocol corpus without collapsing the simulated timeline."""
    buckets: dict[str, list[SessionRecord]] = defaultdict(list)
    candidates = [record for record in records if record.protocol in protocols]
    for record in candidates:
        buckets[record.protocol].append(record)
    if not candidates:
        raise RuntimeError("digital twin produced no selectable protocol rows")

    suspicious_fraction = sum(int(record.label_binary) for record in candidates) / len(candidates)
    base = count // len(protocols)
    remainder = count % len(protocols)
    output: list[SessionRecord] = []
    for index, protocol in enumerate(protocols):
        need = base + (1 if index < remainder else 0)
        bucket = buckets[protocol]
        if len(bucket) < need:
            raise RuntimeError(f"digital twin produced only {len(bucket)} {protocol} rows; need {need}")
        benign_need, suspicious_need = _label_quotas(bucket, need, suspicious_fraction)
        benign_rows = [record for record in bucket if int(record.label_binary) == 0]
        suspicious_rows = [record for record in bucket if int(record.label_binary) == 1]
        output.extend(_evenly_spaced(benign_rows, benign_need))
        output.extend(_evenly_spaced(suspicious_rows, suspicious_need))

    output.sort(key=lambda record: (record.start_ts, record.session_id))
    if len(output) != count:
        raise AssertionError((len(output), count))
    return output


def execute(
    record: SessionRecord,
    namespaces: dict[str, str],
    core_state: Path,
    work: Path,
    netem: dict,
) -> SessionRecord:
    assert_lab(record.src_ip)
    assert_lab(record.dst_ip)
    namespace = namespaces[record.src_host_id]
    started = datetime.now(timezone.utc)
    status = "success"
    try:
        core.apply_netem(namespace, record.netem_profile, netem)
        if record.protocol == "ssh":
            core.run_ssh(record, namespace, core_state, work)
        elif record.protocol == "smb":
            core.run_smb(record, namespace, work)
        elif record.protocol == "rdp":
            run_rdp_session(record, namespace)
        elif record.protocol == "vnc":
            run_vnc_session(record, namespace)
        elif record.protocol == "winrm":
            run_winrm_session(record, namespace)
        else:
            raise RuntimeError(f"unsupported/fidelity-only protocol: {record.protocol}")
    except Exception as exc:
        status = f"failed:{type(exc).__name__}:{str(exc)[:180]}"
    finally:
        core.clear_netem(namespace)
    return replace(
        record,
        execution_start_ts=started.isoformat(),
        execution_end_ts=datetime.now(timezone.utc).isoformat(),
        status=status,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=list("ABCDEFGH"))
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--core-state", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--include-partial-winrm", action="store_true")
    parser.add_argument("--v2-semantic", action="store_true")
    parser.add_argument("--v2-counterfactual-fraction", type=float, default=0.30)
    parser.add_argument("--v3-signal", action="store_true")
    parser.add_argument("--v3-matched-fraction", type=float, default=0.40)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("extended scenario runner requires root")
    if args.v2_semantic and args.v3_signal:
        raise SystemExit("choose either V2 semantic or V3 signal mode, not both")

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    namespaces = namespace_map(topology)
    protocols = CHALLENGE_PROTOCOLS if args.include_partial_winrm else TRAIN_PROTOCOLS
    if args.stage != "H" and args.include_partial_winrm:
        raise SystemExit("partial WinRM is Stage-H challenge only")
    if args.v2_semantic and args.stage != "H":
        raise SystemExit("V2 semantic corpus is Stage H only")
    if args.v3_signal and args.stage != "H":
        raise SystemExit("V3 signal corpus is Stage H only")

    planned = plan_digital_twin_sessions(
        topology,
        scenarios,
        netem,
        bundle,
        seed=args.seed,
        count=max(args.count * 16, args.count + 1600),
        stage=args.stage,
    )
    selected = balanced_select(planned, args.count, protocols)
    selected = organize_campaign_sequences(selected, bundle["campaigns"], seed=args.seed)
    if args.v3_signal:
        selected = build_v3_signal_plan(
            selected,
            seed=args.seed,
            matched_fraction=args.v3_matched_fraction,
        )
    elif args.v2_semantic:
        selected = build_v2_semantic_plan(
            selected,
            seed=args.seed,
            min_counterfactual_fraction=args.v2_counterfactual_fraction,
        )
    selected = materialize_implementation_variants(selected, stage=args.stage, seed=args.seed)
    selected = materialize_wire_controls(selected, bundle["behavior"], seed=args.seed)
    semantic_report = None
    if args.v3_signal:
        semantic_report = audit_v3_signal_plan(selected)
        if float(semantic_report["counterfactual_row_fraction"]) < float(args.v3_matched_fraction):
            raise RuntimeError(f"V3 counterfactual coverage below target: {semantic_report}")
        if float(semantic_report["matched_hour_pair_fraction"]) < 0.80:
            raise RuntimeError(f"V3 exact-hour matching below target: {semantic_report}")
        if float(semantic_report["max_hour_label_fraction_gap"]) > 0.10:
            raise RuntimeError(f"V3 time shortcut audit failed: {semantic_report}")
        if semantic_report["invalid_counterfactual_pairs"]:
            raise RuntimeError(f"invalid V3 counterfactual pairs: {semantic_report['invalid_counterfactual_pairs']}")
    elif args.v2_semantic:
        semantic_report = summarize_v2_plan(selected)
        if float(semantic_report["counterfactual_pair_fraction"]) < float(args.v2_counterfactual_fraction):
            raise RuntimeError(f"V2 counterfactual coverage below target: {semantic_report}")
        if semantic_report["invalid_counterfactual_pairs"]:
            raise RuntimeError(f"invalid V2 counterfactual pairs: {semantic_report['invalid_counterfactual_pairs']}")

    args.out.mkdir(parents=True, exist_ok=True)
    fixtures = args.out / "inert-fixtures"
    fixtures.mkdir(exist_ok=True)
    write_sessions(selected, args.out / "sessions-planned.jsonl")
    executed = [execute(record, namespaces, args.core_state, fixtures, netem) for record in selected]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    statuses = Counter("success" if record.status == "success" else "failed" for record in executed)
    protocol_counts = Counter(record.protocol for record in executed)
    label_counts = Counter("suspicious" if record.label_binary else "benign" for record in executed)
    implementation_counts = Counter(record.implementation_id for record in executed)
    failures = [record.to_dict() for record in executed if record.status != "success"]
    campaigns: dict[str, list[SessionRecord]] = defaultdict(list)
    for record in selected:
        campaigns[record.campaign_id].append(record)
    multi = sum(1 for rows in campaigns.values() if len(rows) >= 3)
    diverse = sum(1 for rows in campaigns.values() if len({record.protocol for record in rows}) >= 2)
    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(statuses),
        "protocol_counts": dict(protocol_counts),
        "label_counts": dict(label_counts),
        "implementation_counts": dict(implementation_counts),
        "protocol_balance_max_minus_min": max(protocol_counts.values()) - min(protocol_counts.values()),
        "campaign_count": len(campaigns),
        "multi_session_campaigns": multi,
        "multi_protocol_campaigns": diverse,
        "train_protocols": list(TRAIN_PROTOCOLS),
        "partial_winrm_included": args.include_partial_winrm,
        "dcerpc_train_included": False,
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "planner": "digital_twin_v3_signal" if args.v3_signal else ("digital_twin_v2_semantic" if args.v2_semantic else "digital_twin_v1"),
        "wire_controls_label_dependent": False,
        "implementation_choice_label_dependent": False,
        "simulated_timeline_preserved": True,
        "selection_policy": "equal protocol quotas; global-label-fraction quotas per protocol; evenly spaced full-timeline sampling; V3 redistributes time-of-day label-neutrally when enabled",
        "v2_semantic": semantic_report if args.v2_semantic else None,
        "v3_signal": semantic_report if args.v3_signal else None,
        "failures": failures[:20],
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    if failures:
        return 1
    if set(protocol_counts) != set(protocols):
        return 1
    if summary["protocol_balance_max_minus_min"] > 1:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
