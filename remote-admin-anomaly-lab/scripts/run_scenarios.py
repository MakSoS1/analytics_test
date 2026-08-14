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

from adminlab.campaign_sequences import organize_campaign_sequences
from adminlab.config import load_yaml
from adminlab.digital_twin import load_digital_twin_bundle, plan_digital_twin_sessions
from adminlab.implementation_variants import materialize_implementation_variants
from adminlab.manifest import SessionRecord, write_sessions
from adminlab.wire_controls import materialize_wire_controls

LAB_NETWORK = ip_network("10.77.0.0/24")
SUPPORTED_PROTOCOLS = {"ssh", "smb"}
VARIANT_CLIENT = ROOT / "scripts/wire_client_variant.py"


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
    p = netem["profiles"][profile_name]
    mtu = int(p.get("mtu", 1500))
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", "eth0", "mtu", str(mtu)])
    args = ["ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", "eth0", "root", "netem"]
    n = 0
    delay = float(p.get("delay_ms", 0))
    jitter = float(p.get("jitter_ms", 0))
    loss = float(p.get("loss_pct", 0))
    reorder = float(p.get("reorder_pct", 0))
    rate = float(p.get("rate_mbit", 0))
    if delay > 0 or jitter > 0:
        args += ["delay", f"{delay:g}ms"]
        n += 1
        if jitter > 0:
            args += [f"{jitter:g}ms"]
    if loss > 0:
        args += ["loss", f"{loss:g}%"]
        n += 1
    if reorder > 0:
        args += ["reorder", f"{reorder:g}%"]
        n += 1
    if rate > 0:
        args += ["rate", f"{rate:g}mbit"]
        n += 1
    if n == 0:
        args += ["delay", "0ms"]
    run(args)


def clear_netem(ns: str) -> None:
    run(["ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", "eth0", "root"], check=False)
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", "eth0", "mtu", "1500"], check=False)


def ssh_base(ns: str, key: Path, dst_ip: str) -> list[str]:
    assert_lab_address(dst_ip)
    return [
        "ip", "netns", "exec", ns, "ssh", "-i", str(key),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
        f"root@{dst_ip}",
    ]


def _transfer_bytes(r: SessionRecord, fallback: int) -> int:
    return int(r.wire_transfer_bytes) if int(r.wire_transfer_bytes) > 0 else fallback


def _attempts(r: SessionRecord) -> int:
    return max(1, int(r.wire_attempts))


def _variant_base(ns: str) -> list[str]:
    return ["ip", "netns", "exec", ns, sys.executable, str(VARIANT_CLIENT)]


def run_ssh(r: SessionRecord, ns: str, state_dir: Path, work_dir: Path) -> None:
    key = state_dir / "ssh/client_ed25519"
    if not key.is_file():
        raise RuntimeError(f"SSH client key missing: {key}")

    if r.client_stack == "paramiko":
        if r.task_id == "approved_forwarding" or r.action == "bounded_proxyjump":
            raise RuntimeError("approved forwarding must use OpenSSH implementation")
        if r.action == "inert_sftp_transfer":
            size = _transfer_bytes(r, 64 * 1024)
            fixture = work_dir / f"inert-{r.session_id}.bin"
            fixture.write_bytes((b"ADMINLAB-INERT-SSH-MARKER\n" * ((size // 26) + 1))[:size])
            cmd = _variant_base(ns) + [
                "paramiko", "--dst", r.dst_ip, "--key", str(key), "--action", "upload",
                "--local", str(fixture), "--remote", f"/tmp/{fixture.name}",
            ]
            for _ in range(_attempts(r)):
                run(cmd, timeout=30)
            return
        reps = _attempts(r) if r.action == "repeated_login" else 1
        cmd = _variant_base(ns) + [
            "paramiko", "--dst", r.dst_ip, "--key", str(key), "--action", "exec",
        ]
        for _ in range(reps):
            run(cmd, timeout=20)
        return

    base = ssh_base(ns, key, r.dst_ip)
    if r.action == "inert_sftp_transfer":
        size = _transfer_bytes(r, 64 * 1024)
        fixture = work_dir / f"inert-{r.session_id}.bin"
        fixture.write_bytes((b"ADMINLAB-INERT-SSH-MARKER\n" * ((size // 26) + 1))[:size])
        scp = [
            "ip", "netns", "exec", ns, "scp", "-q", "-i", str(key),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", str(fixture),
            f"root@{r.dst_ip}:/tmp/{fixture.name}",
        ]
        for _ in range(_attempts(r)):
            run(scp, timeout=30)
        return
    if r.action == "bounded_proxyjump" or r.task_id == "approved_forwarding":
        jump = "10.77.0.21"
        target = "10.77.0.22"
        assert_lab_address(jump)
        assert_lab_address(target)
        proxy = [
            "ip", "netns", "exec", ns, "ssh", "-i", str(key),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
            "-o", f"ProxyCommand=ssh -i {key} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p root@{jump}",
            f"root@{target}", "true",
        ]
        for _ in range(_attempts(r)):
            run(proxy, timeout=20)
        return
    reps = _attempts(r) if r.action == "repeated_login" else 1
    for _ in range(reps):
        run(base + ["printf 'adminlab-session-ok\\n' >/dev/null; true"], timeout=15)


def run_smb(r: SessionRecord, ns: str, work_dir: Path) -> None:
    assert_lab_address(r.dst_ip)
    reps = _attempts(r)

    if r.client_stack == "smbprotocol":
        if r.action == "inert_marker_put":
            size = _transfer_bytes(r, 128 * 1024)
            fixture = work_dir / f"inert-marker-{r.session_id}.bin"
            fixture.write_bytes((b"ADMINLAB-INERT-SMB-MARKER\n" * ((size // 26) + 1))[:size])
            cmd = _variant_base(ns) + [
                "smbprotocol", "--dst", r.dst_ip, "--action", "upload",
                "--local", str(fixture), "--remote", fixture.name,
            ]
        else:
            cmd = _variant_base(ns) + ["smbprotocol", "--dst", r.dst_ip, "--action", "list"]
        for _ in range(reps):
            run(cmd, timeout=30)
        return

    base = [
        "ip", "netns", "exec", ns, "smbclient", f"//{r.dst_ip}/adminlab_admin",
        "-U", "adminlab_smb%AdminlabSMB-2026!", "-m", "SMB3",
    ]
    if r.action == "inert_marker_put":
        size = _transfer_bytes(r, 128 * 1024)
        fixture = work_dir / f"inert-marker-{r.session_id}.bin"
        fixture.write_bytes((b"ADMINLAB-INERT-SMB-MARKER\n" * ((size // 26) + 1))[:size])
        for _ in range(reps):
            run(base + ["-c", f"put {fixture} {fixture.name}"], timeout=30)
    else:
        for _ in range(reps):
            run(base + ["-c", "ls; get readme.txt /tmp/adminlab-readme.txt"], timeout=20)


def execute_record(
    r: SessionRecord,
    ns_by_host: dict[str, str],
    state_dir: Path,
    work_dir: Path,
    netem: dict,
) -> SessionRecord:
    assert_lab_address(r.src_ip)
    assert_lab_address(r.dst_ip)
    ns = ns_by_host[r.src_host_id]
    started = datetime.now(timezone.utc)
    status = "success"
    try:
        apply_netem(ns, r.netem_profile, netem)
        if r.protocol == "ssh":
            run_ssh(r, ns, state_dir, work_dir)
        elif r.protocol == "smb":
            run_smb(r, ns, work_dir)
        else:
            status = "unsupported"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError, ValueError) as exc:
        status = f"failed:{type(exc).__name__}:{str(exc)[:180]}"
    finally:
        clear_netem(ns)
    return replace(
        r,
        execution_start_ts=started.isoformat(),
        execution_end_ts=datetime.now(timezone.utc).isoformat(),
        status=status,
    )


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
    protocols = {x.strip() for x in args.protocols.split(",") if x.strip()}
    if not protocols or not protocols <= SUPPORTED_PROTOCOLS:
        raise SystemExit(f"V1 core runner supports only {sorted(SUPPORTED_PROTOCOLS)}")

    topology = load_yaml(ROOT / "configs/topology.yaml")
    scenarios = load_yaml(ROOT / "configs/scenarios.yaml")
    netem = load_yaml(ROOT / "configs/netem.yaml")
    bundle = load_digital_twin_bundle(ROOT / "configs")
    nsmap = namespace_by_host(topology)
    planned = plan_digital_twin_sessions(
        topology, scenarios, netem, bundle,
        seed=args.seed, count=max(args.count * 12, 240), stage=args.stage,
    )
    selected = select_supported(planned, args.count, protocols)
    selected = organize_campaign_sequences(selected, bundle["campaigns"], seed=args.seed)
    selected = materialize_implementation_variants(selected, stage=args.stage, seed=args.seed)
    records = materialize_wire_controls(selected, bundle["behavior"], seed=args.seed)

    args.out.mkdir(parents=True, exist_ok=True)
    work = args.out / "inert-fixtures"
    work.mkdir(parents=True, exist_ok=True)
    write_sessions(records, args.out / "sessions-planned.jsonl")
    executed = [execute_record(r, nsmap, args.state_dir, work, netem) for r in records]
    write_sessions(executed, args.out / "sessions-executed.jsonl")

    statuses = Counter(r.status for r in executed)
    protocol_counts = Counter(r.protocol for r in executed)
    label_counts = Counter("suspicious" if r.label_binary else "benign" for r in executed)
    implementation_counts = Counter(r.implementation_id for r in executed)
    success = {
        protocol: sum(1 for r in executed if r.protocol == protocol and r.status == "success")
        for protocol in sorted(protocols)
    }
    campaigns = {r.campaign_id for r in records}
    multi = sum(1 for cid in campaigns if sum(1 for r in records if r.campaign_id == cid) >= 3)
    summary = {
        "requested": args.count,
        "executed": len(executed),
        "status_counts": dict(statuses),
        "protocol_counts": dict(protocol_counts),
        "label_counts": dict(label_counts),
        "implementation_counts": dict(implementation_counts),
        "success_by_protocol": success,
        "campaign_count": len(campaigns),
        "multi_session_campaigns": multi,
        "lab_network": str(LAB_NETWORK),
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "planner": "digital_twin_v1",
        "wire_controls_label_dependent": False,
        "implementation_choice_label_dependent": False,
        "simulated_timeline_preserved": True,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    if statuses.get("success", 0) != len(executed):
        return 1
    if any(success.get(protocol, 0) == 0 for protocol in protocols):
        return 1
    if len(label_counts) < 2 and args.stage != "B":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
