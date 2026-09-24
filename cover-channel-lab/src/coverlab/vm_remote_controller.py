from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

SAFE_SSH = re.compile(r"^[A-Za-z0-9_.-]+@[0-9A-Fa-f:.]+$")
SAFE_POSIX_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")
SAFE_WINDOWS_PATH = re.compile(r"^[A-Za-z]:/[A-Za-z0-9_./-]+$")


def run(cmd: list[str], *, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def validate_target(target: str) -> None:
    if not SAFE_SSH.fullmatch(target):
        raise ValueError(f"unsafe ssh target: {target}")
    host = target.split("@", 1)[1]
    ip = ipaddress.ip_address(host)
    if not ip.is_private or ip.is_loopback:
        raise ValueError(f"ssh target must be a private lab address: {target}")


def validate_path(path: str, os_name: str) -> None:
    rx = SAFE_WINDOWS_PATH if os_name == "windows" else SAFE_POSIX_PATH
    if not rx.fullmatch(path):
        raise ValueError(f"unsafe {os_name} path: {path}")


def ssh_base(key: str | None) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
    if key:
        cmd += ["-i", key]
    return cmd


def scp_base(key: str | None) -> list[str]:
    cmd = ["scp", "-q", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
    if key:
        cmd += ["-i", key]
    return cmd


def remote_posix(target: str, command: str, key: str | None) -> None:
    validate_target(target)
    run(ssh_base(key) + [target, command])


def remote_windows(target: str, command: str, key: str | None) -> None:
    validate_target(target)
    run(ssh_base(key) + [target, command])


def remote_posix_capture(target: str, command: str, key: str | None) -> str:
    validate_target(target)
    cp = run(ssh_base(key) + [target, command], capture=True)
    return cp.stdout or ""


def start_sensor_capture(inv: dict, work: Path, key: str | None) -> tuple[str, str, str]:
    cap = inv.get("capture") or {}
    target = str(cap.get("sensor_host") or "")
    iface = str(cap.get("interface") or "")
    fmt = str(cap.get("format") or "pcapng").lower()
    remote_work = str(cap.get("work_dir") or "/tmp/coverlab-vm-sensor")
    validate_target(target)
    validate_path(remote_work, "linux")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", iface):
        raise ValueError(f"unsafe capture interface: {iface}")
    if fmt != "pcapng":
        raise ValueError("VM wire master capture must use pcapng")
    remote_file = remote_work + "/capture.pcapng"
    remote_pid = remote_work + "/dumpcap.pid"
    remote_log = remote_work + "/dumpcap.log"
    command = (
        f"mkdir -p {shlex.quote(remote_work)} && "
        f"command -v dumpcap >/dev/null && "
        f"rm -f {shlex.quote(remote_file)} {shlex.quote(remote_pid)} {shlex.quote(remote_log)} && "
        f"nohup dumpcap -q -i {shlex.quote(iface)} -f {shlex.quote('net 10.20.0.0/24')} "
        f"-w {shlex.quote(remote_file)} >{shlex.quote(remote_log)} 2>&1 & echo $! > {shlex.quote(remote_pid)}"
    )
    remote_posix(target, command, key)
    # Confirm the capture process actually stayed alive before generating traffic.
    remote_posix(target, f"sleep 1; test -s {shlex.quote(remote_pid)}; kill -0 $(cat {shlex.quote(remote_pid)})", key)
    return target, remote_file, remote_pid


def stop_sensor_capture(target: str, remote_file: str, remote_pid: str, local_file: Path, key: str | None) -> None:
    command = (
        f"if test -s {shlex.quote(remote_pid)}; then "
        f"kill -INT $(cat {shlex.quote(remote_pid)}) 2>/dev/null || true; "
        f"for i in $(seq 1 50); do kill -0 $(cat {shlex.quote(remote_pid)}) 2>/dev/null || break; sleep 0.1; done; fi; "
        f"test -s {shlex.quote(remote_file)}"
    )
    remote_posix(target, command, key)
    local_file.parent.mkdir(parents=True, exist_ok=True)
    run(scp_base(key) + [f"{target}:{remote_file}", str(local_file)])


def collect_server_ground_truth(inv: dict, out: Path, key: str | None) -> None:
    server = inv.get("server") or {}
    target = str(server.get("ssh") or "")
    validate_target(target)
    text = remote_posix_capture(
        target,
        "for f in /tmp/coverlab_server_trace.jsonl /tmp/coverlab_wss_trace.jsonl; do "
        "test -f \"$f\" && cat \"$f\" || true; done",
        key,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)


def split_plan(plan: Path) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for line in plan.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        grouped.setdefault(str(row["client_id"]), []).append(row)
    return grouped


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(x, separators=(",", ":")) for x in rows) + ("\n" if rows else ""))


def bootstrap_services(inv: dict, key: str | None) -> None:
    server = inv["server"]
    resolver = inv.get("resolver")
    for node, script in ((server, "start_server.sh"), (resolver, "start_resolver.sh")):
        if not node:
            continue
        target = str(node["ssh"])
        repo = str(node["repo_path"])
        validate_target(target)
        validate_path(repo, "linux")
        command = f"cd {shlex.quote(repo)} && bash {shlex.quote('vm/' + script)}"
        remote_posix(target, command, key)

    # Make the local .test topology explicit on every client. This avoids
    # depending on public DNS or per-host manual state.
    for client in inv["clients"]:
        target = str(client["ssh"])
        repo = str(client["repo_path"]).rstrip("/")
        validate_target(target)
        if client["os"] == "linux":
            validate_path(repo, "linux")
            remote_posix(
                target,
                f"cd {shlex.quote(repo)} && bash vm/configure_linux_hosts.sh",
                key,
            )
        else:
            validate_path(repo, "windows")
            script = repo + "/vm/configure_windows_hosts.ps1"
            remote_windows(
                target,
                'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + f'"{script}"',
                key,
            )


def verify_remote_revision(inv: dict, key: str | None) -> None:
    expected = os.environ.get("GITHUB_SHA", "").strip()
    if not expected or expected == "local":
        return
    nodes = [
        ("server", inv.get("server")),
        ("resolver", inv.get("resolver")),
        ("router", inv.get("router")),
        *[(f"client:{c.get('id')}", c) for c in inv.get("clients", [])],
    ]
    mismatches = []
    for label, node in nodes:
        if not node or not node.get("ssh") or not node.get("repo_path"):
            continue
        target = str(node["ssh"])
        repo = str(node["repo_path"]).rstrip("/")
        os_name = str(node.get("os") or "linux")
        validate_target(target)
        validate_path(repo, "windows" if os_name == "windows" else "linux")
        if os_name == "windows":
            cmd = f'powershell.exe -NoProfile -Command "git -C \'{repo}\' rev-parse HEAD"'
        else:
            cmd = f"git -C {shlex.quote(repo)} rev-parse HEAD"
        try:
            actual = remote_posix_capture(target, cmd, key).strip().splitlines()[-1]
        except Exception as exc:
            mismatches.append(f"{label}: cannot read revision ({exc})")
            continue
        if actual != expected:
            mismatches.append(f"{label}: {actual} != {expected}")
    if mismatches:
        raise RuntimeError(
            "VM nodes must run the same CoverLab revision as the controller: " + "; ".join(mismatches)
        )


def apply_netem(inv: dict, profile: str, key: str | None) -> None:
    router = inv["router"]
    target = str(router["ssh"])
    repo = str(router.get("repo_path") or "/opt/coverlab/analytics_test/cover-channel-lab")
    validate_target(target)
    validate_path(repo, "linux")
    client_if = str(router["client_interface"])
    server_if = str(router["server_interface"])
    for value in (client_if, server_if):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise ValueError(f"unsafe interface name: {value}")
    if profile not in {"lan", "wan_low", "wan", "bad_wifi", "asymmetric", "clear"}:
        raise ValueError(f"invalid netem profile: {profile}")
    command = (
        f"cd {shlex.quote(repo)} && bash vm/apply_router_netem.sh "
        f"{shlex.quote(profile)} {shlex.quote(client_if)} {shlex.quote(server_if)}"
    )
    remote_posix(target, command, key)


def run_linux_client(client: dict, rows: list[dict], work: Path, key: str | None, *, event_cap: int, time_scale: float, max_sleep: str) -> Path:
    target = str(client["ssh"])
    repo = str(client["repo_path"])
    remote_work = str(client["work_dir"]).rstrip("/")
    validate_target(target)
    validate_path(repo, "linux")
    validate_path(remote_work, "linux")
    local_plan = work / f"plan-{client['id']}.jsonl"
    write_jsonl(local_plan, rows)
    remote_plan = remote_work + "/plan.jsonl"
    remote_out = remote_work + "/out"
    remote_posix(target, f"mkdir -p {shlex.quote(remote_work)} {shlex.quote(remote_out)}", key)
    run(scp_base(key) + [str(local_plan), f"{target}:{remote_plan}"])
    env = [
        "PYTHONPATH=src",
        "COVERLAB_ENVIRONMENT_TIER=vm_wire",
        f"COVERLAB_STAGE_M_TIME_SCALE={time_scale}",
        f"COVERLAB_STAGE_M_EVENT_COUNT_CAP={event_cap}",
    ]
    if max_sleep == "":
        env.append("COVERLAB_STAGE_M_MAX_SLEEP_SECONDS=")
    else:
        env.append(f"COVERLAB_STAGE_M_MAX_SLEEP_SECONDS={max_sleep}")
    command = (
        f"cd {shlex.quote(repo)} && "
        + " ".join(shlex.quote(x) for x in env)
        + f" python3 -m coverlab.vm_linux_agent --plan {shlex.quote(remote_plan)} "
        + f"--out {shlex.quote(remote_out)} --capture-file capture.pcapng"
    )
    remote_posix(target, command, key)
    local_out = work / f"result-{client['id']}"
    local_out.mkdir(parents=True, exist_ok=True)
    for name in ("campaigns.jsonl", "events.jsonl"):
        run(scp_base(key) + [f"{target}:{remote_out}/{name}", str(local_out / name)])
    return local_out


def run_windows_client(
    client: dict, rows: list[dict], work: Path, key: str | None, *,
    event_cap: int, time_scale: float, max_sleep: str,
) -> Path:
    target = str(client["ssh"])
    repo = str(client["repo_path"]).rstrip("/")
    remote_work = str(client["work_dir"]).rstrip("/")
    validate_target(target)
    validate_path(repo, "windows")
    validate_path(remote_work, "windows")
    local_plan = work / f"plan-{client['id']}.jsonl"
    write_jsonl(local_plan, rows)
    remote_plan = remote_work + "/plan.jsonl"
    remote_out = remote_work + "/out"
    remote_windows(target, f'powershell.exe -NoProfile -Command "New-Item -ItemType Directory -Force -Path \'{remote_work}\' | Out-Null"', key)
    run(scp_base(key) + [str(local_plan), f"{target}:{remote_plan}"])
    batch = repo + "/vm/windows_stage_m_batch.ps1"
    agent = repo + "/vm/windows_stage_m_agent.ps1"
    max_sleep_num = -1.0 if max_sleep == "" else float(max_sleep)
    command = (
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File '
        + f'"{batch}" -Plan "{remote_plan}" -Agent "{agent}" -OutDir "{remote_out}" '
        + f'-EventCap {event_cap} -TimeScale {time_scale} -MaxSleepSeconds {max_sleep_num}'
    )
    remote_windows(target, command, key)
    local_out = work / f"result-{client['id']}"
    local_out.mkdir(parents=True, exist_ok=True)
    for name in ("campaigns.jsonl", "events.jsonl"):
        run(scp_base(key) + [f"{target}:{remote_out}/{name}", str(local_out / name)])
    return local_out


def merge(results: list[Path], out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    counts = {"campaigns": 0, "events": 0}
    for name, key_name in (("campaigns.jsonl", "campaigns"), ("events.jsonl", "events")):
        dst = out / name
        with dst.open("w", encoding="utf-8") as w:
            for root in results:
                src = root / name
                if not src.exists():
                    continue
                for line in src.read_text(errors="replace").splitlines():
                    if line.strip():
                        w.write(line + "\n")
                        counts[key_name] += 1
    return counts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--netem-profile", default="lan")
    ap.add_argument("--ssh-key")
    ap.add_argument("--bootstrap-services", action="store_true")
    ap.add_argument("--event-cap", type=int, default=0)
    ap.add_argument("--time-scale", type=float, default=0.001)
    ap.add_argument("--max-sleep", default="0.05")
    ap.add_argument("--capture-wire", action="store_true")
    a = ap.parse_args()

    inv = json.loads(Path(a.inventory).read_text())
    clients = {str(x["id"]): x for x in inv["clients"]}
    sensor_node = {"ssh": (inv.get("capture") or {}).get("sensor_host")}
    for node in [inv.get("server"), inv.get("resolver"), inv.get("router"), sensor_node, *inv["clients"]]:
        if node and node.get("ssh"):
            validate_target(str(node["ssh"]))

    verify_remote_revision(inv, a.ssh_key)
    if a.bootstrap_services:
        bootstrap_services(inv, a.ssh_key)
    apply_netem(inv, a.netem_profile, a.ssh_key)

    grouped = split_plan(Path(a.plan))
    out_root = Path(a.out)
    work = out_root / "remote"
    work.mkdir(parents=True, exist_ok=True)
    capture_state: tuple[str, str, str] | None = None
    results = []
    try:
        if a.capture_wire:
            capture_state = start_sensor_capture(inv, work, a.ssh_key)
        for client_id, rows in sorted(grouped.items()):
            client = clients[client_id]
            if client["os"] == "linux":
                results.append(run_linux_client(
                    client, rows, work, a.ssh_key,
                    event_cap=a.event_cap, time_scale=a.time_scale, max_sleep=a.max_sleep,
                ))
            else:
                results.append(run_windows_client(
                    client, rows, work, a.ssh_key,
                    event_cap=a.event_cap, time_scale=a.time_scale, max_sleep=a.max_sleep,
                ))
    finally:
        if capture_state is not None:
            target, remote_file, remote_pid = capture_state
            stop_sensor_capture(target, remote_file, remote_pid, out_root / "capture.pcapng", a.ssh_key)
    counts = merge(results, out_root / "merged")
    collect_server_ground_truth(inv, out_root / "merged" / "decrypted_transactions.jsonl", a.ssh_key)
    print(json.dumps({
        **counts,
        "clients": len(results),
        "positive_only": True,
        "capture_environment": "vm_wire",
        "wire_capture": bool(a.capture_wire),
        "pcapng": str(out_root / "capture.pcapng") if a.capture_wire else None,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
