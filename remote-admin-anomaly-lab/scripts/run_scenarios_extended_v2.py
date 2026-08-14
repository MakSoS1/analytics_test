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

from adminlab.config import load_yaml  # noqa: E402
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions  # noqa: E402
from adminlab.extended_wire_v2 import run_rdp_session, run_vnc_session, run_winrm_session  # noqa: E402
from adminlab.manifest import SessionRecord, write_sessions  # noqa: E402

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


def balanced_select(records: list[SessionRecord], count: int, protocols: tuple[str, ...]) -> list[SessionRecord]:
    buckets: dict[str, list[SessionRecord]] = defaultdict(list)
    for row in records:
        if row.protocol in protocols:
            buckets[row.protocol].append(row)
    base = count // len(protocols)
    remainder = count % len(protocols)
    selected: list[SessionRecord] = []
    required: dict[str, int] = {}
    for idx, protocol in enumerate(protocols):
        need = base + (1 if idx < remainder else 0)
        required[protocol] = need
        if len(buckets[protocol]) < need:
            raise RuntimeError(
                f"digital twin produced only {len(buckets[protocol])} {protocol} rows; need {need}"
            )
        selected.extend(buckets[protocol][:need])
    selected.sort(key=lambda row: (row.start_ts, row.session_id))
    if len(selected) != count:
        raise AssertionError((len(selected), count, required))
    return selected


def execute(record: SessionRecord, namespaces: dict[str, str], core_state: Path, work: Path, netem: dict) -> SessionRecord:
    assert_lab(record.src_ip)
    assert_lab(record.dst_ip)
    ns = namespaces[record.src_host_id]
    started = datetime.now(timezone.utc)
    status = "success"
    try:
        core.apply_netem(ns, record.netem_profile, netem)
        if record.protocol == "ssh":
            core.run_ssh(record, ns, core_state, work)
        elif record.protocol == "smb":
            core.run_smb(record, ns, work)
        elif record.protocol == "rdp":
            run_rdp_session(record, ns)
        elif record.protocol == "vnc":
            run_vnc_session(record, ns)
        elif record.protocol == "winrm":
            run_winrm_session(record, ns)
        else:
            raise RuntimeError(f"unsupported/fidelity-only protocol: {record.protocol}")
    except Exception as exc:
        status = f"failed:{type(exc).__name__}:{str(exc)[:180]}"
    finally:
        core.clear_netem(ns)
    ended = datetime.now(timezone.utc)
    # Preserve execution timestamps for PCAP mapping. Simulated organizational
    # day/persona/task context remains in explicit manifest fields.
    return replace(record, start_ts=started.isoformat(), end_ts=ended.isoformat(), status=status)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=list("ABCDEFGH"))
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--core-state", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--include-partial-winrm", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("extended scenario runner requires root")

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    namespaces = namespace_map(topology)
    protocols = CHALLENGE_PROTOCOLS if args.include_partial_winrm else TRAIN_PROTOCOLS
    if args.stage != "H" and args.include_partial_winrm:
        raise SystemExit("partial WinRM is Stage-H challenge only")

    oversample = max(args.count * 16, args.count + 1600)
    planned = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle, seed=args.seed, count=oversample, stage=args.stage
    )
    selected = balanced_select(planned, args.count, protocols)

    args.out.mkdir(parents=True, exist_ok=True)
    fixtures = args.out / "inert-fixtures"
    fixtures.mkdir(exist_ok=True)
    write_sessions(selected, args.out / "sessions-planned.jsonl")
    executed = [execute(row, namespaces, args.core_state, fixtures, netem) for row in selected]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    status_counts = Counter("success" if row.status == "success" else "failed" for row in executed)
    protocol_counts = Counter(row.protocol for row in executed)
    label_counts = Counter("suspicious" if row.label_binary else "benign" for row in executed)
    failures = [row.to_dict() for row in executed if row.status != "success"]
    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(status_counts),
        "protocol_counts": dict(protocol_counts),
        "label_counts": dict(label_counts),
        "protocol_balance_max_minus_min": max(protocol_counts.values()) - min(protocol_counts.values()),
        "train_protocols": list(TRAIN_PROTOCOLS),
        "partial_winrm_included": args.include_partial_winrm,
        "dcerpc_train_included": False,
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "planner": "digital_twin_v1",
        "wire_controls_label_dependent": False,
        "failures": failures[:20],
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
