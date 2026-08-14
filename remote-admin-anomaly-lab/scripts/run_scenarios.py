#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
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
from adminlab.manifest import SessionRecord, write_sessions  # noqa: E402
from adminlab.scenarios import plan_sessions  # noqa: E402

LAB_NETWORK = ip_network("10.77.0.0/24")
SUPPORTED_PROTOCOLS = {"ssh", "smb"}


def run(cmd: list[str], *, check: bool = True, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def assert_lab_address(address: str) -> None:
    if ip_address(address) not in LAB_NETWORK:
        raise ValueError(f"destination outside isolated lab: {address}")


def namespace_by_host(topology: dict) -> dict[str, str]:
    return {str(h["id"]): str(h["namespace"]) for h in topology["hosts"]}


def apply_netem(ns: str, profile_name: str, netem: dict) -> None:
    profile = netem["profiles"][profile_name]
    mtu = int(profile.get("mtu", 1500))
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", "eth0", "mtu", str(mtu)])
    args = ["ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", "eth0", "root", "netem"]
    option_count = 0
    delay = float(profile.get("delay_ms", 0))
    jitter = float(profile.get("jitter_ms", 0))
    loss = float(profile.get("loss_pct", 0))
    reorder = float(profile.get("reorder_pct", 0))
    rate = float(profile.get("rate_mbit", 0))
    if delay > 0 or jitter > 0:
        args += ["delay", f"{delay:g}ms"]
        if jitter > 0:
            args += [f"{jitter:g}ms"]
        option_count += 1
    if loss > 0:
        args += ["loss", f"{loss:g}%"]
        option_count += 1
    if reorder > 0:
        args += ["reorder", f"{reorder:g}%"]
        option_count += 1
    if rate > 0:
        args += ["rate", f"{rate:g}mbit"]
        option_count += 1
    if option_count == 0:
        args += ["delay", "0ms"]
    run(args)


def clear_netem(ns: str) -> None:
    run(["ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", "eth0", "root"], check=False)
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", "eth0", "mtu", "1500"], check=False)


def ssh_base(ns: str, key: Path, dst_ip: str) -> list[str]:
    assert_lab_address(dst_ip)
    return [
        "ip",
        "netns",
        "exec",
        ns,
        "ssh",
        "-i",
        str(key),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        f"root@{dst_ip}",
    ]


def run_ssh(record: SessionRecord, ns: str, state_dir: Path, work_dir: Path) -> None:
    key = state_dir / "ssh/client_ed25519"
    if not key.is_file():
        raise RuntimeError(f"SSH client key missing: {key}")
    base = ssh_base(ns, key, record.dst_ip)

    if record.action == "inert_sftp_transfer":
        size = 32 * 1024 if record.label_binary == 0 else 256 * 1024
        inert = work_dir / f"inert-{record.session_id}.bin"
        inert.write_bytes((b"ADMINLAB-INERT-SSH-MARKER\n" * ((size // 26) + 1))[:size])
        scp = [
            "ip",
            "netns",
            "exec",
            ns,
            "scp",
            "-q",
            "-i",
            str(key),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            str(inert),
            f"root@{record.dst_ip}:/tmp/{inert.name}",
        ]
        run(scp, timeout=30)
        return

    repetitions = 1
    if record.action == "repeated_login":
        repetitions = 2 if record.label_binary == 0 else 6
    for _ in range(repetitions):
        run(base + ["printf 'adminlab-session-ok\\n' >/dev/null; true"], timeout=15)


def run_smb(record: SessionRecord, ns: str, work_dir: Path) -> None:
    assert_lab_address(record.dst_ip)
    base = [
        "ip",
        "netns",
        "exec",
        ns,
        "smbclient",
        f"//{record.dst_ip}/public",
        "-N",
        "-m",
        "SMB3",
    ]
    if record.action == "inert_marker_put":
        size = 64 * 1024 if record.label_binary == 0 else 512 * 1024
        marker = work_dir / f"inert-marker-{record.session_id}.bin"
        marker.write_bytes((b"ADMINLAB-INERT-SMB-MARKER\n" * ((size // 26) + 1))[:size])
        run(base + ["-c", f"put {marker} {marker.name}"], timeout=30)
    else:
        run(base + ["-c", "ls; get readme.txt /tmp/adminlab-readme.txt"], timeout=20)


def execute_record(record: SessionRecord, ns_by_host: dict[str, str], state_dir: Path, work_dir: Path, netem: dict) -> SessionRecord:
    assert_lab_address(record.src_ip)
    assert_lab_address(record.dst_ip)
    ns = ns_by_host[record.src_host_id]
    started = datetime.now(timezone.utc)
    status = "success"
    try:
        apply_netem(ns, record.netem_profile, netem)
        if record.protocol == "ssh":
            run_ssh(record, ns, state_dir, work_dir)
        elif record.protocol == "smb":
            run_smb(record, ns, work_dir)
        else:
            status = "unsupported"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError, ValueError) as exc:
        status = f"failed:{type(exc).__name__}"
    finally:
        clear_netem(ns)
    ended = datetime.now(timezone.utc)
    return replace(record, start_ts=started.isoformat(), end_ts=ended.isoformat(), status=status)


def select_supported(records: list[SessionRecord], count: int, protocols: set[str]) -> list[SessionRecord]:
    selected = [r for r in records if r.protocol in protocols]
    if len(selected) < count:
        raise RuntimeError(f"planner produced only {len(selected)} supported sessions, need {count}")
    return selected[:count]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", default="A", choices=list("ABCDEFGH"))
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20260814)
    parser.add_argument("--protocols", default="ssh,smb")
    parser.add_argument("--state-dir", type=Path, default=Path("/tmp/adminlab-services"))
    parser.add_argument("--out", type=Path, default=Path("/tmp/adminlab-wire-smoke"))
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("run_scenarios.py must run as root because it uses ip netns exec")

    protocols = {p.strip() for p in args.protocols.split(",") if p.strip()}
    if not protocols or not protocols <= SUPPORTED_PROTOCOLS:
        raise SystemExit(f"V1 core runner supports only {sorted(SUPPORTED_PROTOCOLS)}")

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    ns_by_host = namespace_by_host(topology)

    planned = plan_sessions(topology, scenarios, netem, seed=args.seed, count=max(args.count * 12, 240), stage=args.stage)
    records = select_supported(planned, args.count, protocols)

    args.out.mkdir(parents=True, exist_ok=True)
    work_dir = args.out / "inert-fixtures"
    work_dir.mkdir(parents=True, exist_ok=True)
    write_sessions(records, args.out / "sessions-planned.jsonl")

    executed = [execute_record(r, ns_by_host, args.state_dir, work_dir, netem) for r in records]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    status_counts = Counter(r.status for r in executed)
    protocol_counts = Counter(r.protocol for r in executed)
    label_counts = Counter("suspicious" if r.label_binary else "benign" for r in executed)
    success_by_protocol = {
        protocol: sum(1 for r in executed if r.protocol == protocol and r.status == "success")
        for protocol in sorted(protocols)
    }
    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(status_counts),
        "protocol_counts": dict(protocol_counts),
        "label_counts": dict(label_counts),
        "success_by_protocol": success_by_protocol,
        "lab_network": str(LAB_NETWORK),
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))

    if status_counts.get("success", 0) != len(executed):
        return 1
    if any(success_by_protocol.get(protocol, 0) == 0 for protocol in protocols):
        return 1
    if len(label_counts) < 2:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
