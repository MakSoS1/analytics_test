#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.config import load_yaml  # noqa: E402
from adminlab.extended_wire import run_rdp_session, run_vnc_session, run_winrm_session  # noqa: E402
from adminlab.manifest import SessionRecord, write_sessions  # noqa: E402
from adminlab.scenarios import plan_sessions  # noqa: E402

spec = importlib.util.spec_from_file_location("adminlab_core_wire", ROOT / "scripts/run_scenarios.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load core wire runner")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

LAB_NETWORK = ip_network("10.77.0.0/24")
TRAIN_PROTOCOLS = {"ssh", "smb", "rdp", "vnc"}
CHALLENGE_PROTOCOLS = TRAIN_PROTOCOLS | {"winrm"}


def namespace_map(topology: dict) -> dict[str, str]:
    return {str(h["id"]): str(h["namespace"]) for h in topology["hosts"]}


def assert_lab(value: str) -> None:
    if ip_address(value) not in LAB_NETWORK:
        raise RuntimeError(f"non-lab address rejected: {value}")


def choose_records(records: list[SessionRecord], count: int, protocols: set[str]) -> list[SessionRecord]:
    eligible = [row for row in records if row.protocol in protocols]
    if len(eligible) < count:
        raise RuntimeError(f"only {len(eligible)} eligible sessions generated for {count} requested")
    if any(row.protocol == "dcerpc" for row in eligible[:count]):
        raise RuntimeError("partial DCE/RPC/DCOM fixture must not enter corpus runner")
    return eligible[:count]


def execute(
    record: SessionRecord,
    namespaces: dict[str, str],
    core_state: Path,
    work: Path,
    netem: dict,
) -> SessionRecord:
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
            raise RuntimeError(f"unsupported or fidelity-only protocol: {record.protocol}")
    except Exception as exc:  # execution status is evidence; the shard gate decides whether to reject
        status = f"failed:{type(exc).__name__}:{str(exc)[:180]}"
    finally:
        core.clear_netem(ns)
    ended = datetime.now(timezone.utc)
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
        raise SystemExit("extended scenario runner requires root for namespaces/netem")

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    namespaces = namespace_map(topology)
    protocols = CHALLENGE_PROTOCOLS if args.include_partial_winrm else TRAIN_PROTOCOLS
    if args.stage != "H" and "winrm" in protocols:
        raise SystemExit("partial WinRM is challenge-only")

    # Oversample because the canonical planner also contains fidelity-only DCE/RPC.
    planned = plan_sessions(
        topology,
        scenarios,
        netem,
        seed=args.seed,
        count=max(args.count * 4, args.count + 200),
        stage=args.stage,
    )
    selected = choose_records(planned, args.count, protocols)

    args.out.mkdir(parents=True, exist_ok=True)
    fixtures = args.out / "inert-fixtures"
    fixtures.mkdir(exist_ok=True)
    write_sessions(selected, args.out / "sessions-planned.jsonl")
    executed = [execute(row, namespaces, args.core_state, fixtures, netem) for row in selected]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    status = Counter("success" if row.status == "success" else "failed" for row in executed)
    protocols_seen = Counter(row.protocol for row in executed)
    labels = Counter("suspicious" if row.label_binary else "benign" for row in executed)
    failures = [row.to_dict() for row in executed if row.status != "success"]
    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(status),
        "protocol_counts": dict(protocols_seen),
        "label_counts": dict(labels),
        "allowed_train_protocols": sorted(TRAIN_PROTOCOLS),
        "partial_winrm_included": args.include_partial_winrm,
        "dcerpc_train_included": False,
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "failures": failures[:20],
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))

    if failures:
        return 1
    expected = TRAIN_PROTOCOLS if not args.include_partial_winrm else CHALLENGE_PROTOCOLS
    if args.count >= 40 and not expected.issubset(set(protocols_seen)):
        return 1
    if len(labels) < 2 and args.stage not in {"B", "C", "D", "E"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
