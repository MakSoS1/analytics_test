from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .manifest import SessionRecord


def run(cmd: list[str], *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        timeout=timeout,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ns_exec(namespace: str, command: list[str], *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", namespace, *command], timeout=timeout, check=check)


def tool(*names: str) -> str | None:
    for name in names:
        value = shutil.which(name)
        if value:
            return value
    return None


def wait_listener(namespace: str, port: int, seconds: float = 8.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        result = ns_exec(
            namespace,
            ["ss", "-H", "-ltn", "sport", "=", f":{port}"],
            timeout=5,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
        time.sleep(0.2)
    return False


def start_group(namespace: str, command: list[str], log: Path) -> subprocess.Popen[str]:
    log.parent.mkdir(parents=True, exist_ok=True)
    handle = log.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        ["setsid", "ip", "netns", "exec", namespace, *command],
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proc._adminlab_log_handle = handle  # type: ignore[attr-defined]
    return proc


def stop_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=2)
    handle = getattr(proc, "_adminlab_log_handle", None)
    if handle is not None:
        handle.close()


def free_rdp_client() -> str | None:
    return tool("xfreerdp3", "xfreerdp", "sdl-freerdp")


def run_rdp_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    client = free_rdp_client()
    if client is None:
        raise RuntimeError("FreeRDP client is unavailable")
    repetitions = 1 if record.label_binary == 0 else 4
    results: list[int] = []
    for _ in range(repetitions):
        base = [
            client,
            f"/v:{record.dst_ip}:3389",
            "/u:adminlab",
            "/p:AdminlabOnly-2026!",
            "/cert:ignore",
        ]
        if Path(client).name.startswith("xfreerdp"):
            base += ["/auth-only", "/timeout:5000"]
        completed = ns_exec(namespace, base, timeout=15, check=False)
        results.append(completed.returncode)
        # A real transport/negotiation attempt is the Linux-xrdp wire claim.
        # The corpus does not claim a rendered Windows desktop.
        if completed.returncode not in (0, 1, 131):
            raise RuntimeError(
                f"FreeRDP transport failed rc={completed.returncode}: {completed.stderr[-400:]}"
            )
    return {"attempts": repetitions, "return_codes": results, "semantic_fidelity": "partial_windows"}


def run_vnc_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    repetitions = 1 if record.label_binary == 0 else 5
    code = r'''
import socket,sys
host=sys.argv[1]
s=socket.create_connection((host,5900),5)
banner=s.recv(12)
assert banner.startswith(b'RFB '), banner
s.sendall(banner)
sec=s.recv(64)
assert sec, sec
s.close()
'''
    for _ in range(repetitions):
        completed = ns_exec(namespace, ["python3", "-c", code, record.dst_ip], timeout=10, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"RFB negotiation failed: {completed.stderr[-400:]}")
    return {"attempts": repetitions, "semantic_fidelity": "partial_client_interaction"}


def run_winrm_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    curl = tool("curl")
    if curl is None:
        raise RuntimeError("curl unavailable for WS-Man fixture")
    repetitions = 1 if record.label_binary == 0 else 5
    soap = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        '<s:Body><w:Identify/></s:Body></s:Envelope>'
    )
    for _ in range(repetitions):
        completed = ns_exec(
            namespace,
            [
                curl,
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "-H",
                "Content-Type: application/soap+xml",
                "--data",
                soap,
                f"http://{record.dst_ip}:5985/wsman",
            ],
            timeout=10,
            check=False,
        )
        if completed.returncode != 0 or "IdentifyResponse" not in completed.stdout:
            raise RuntimeError(
                f"WS-Man fixture failed rc={completed.returncode}: {completed.stderr[-400:]}"
            )
    return {"attempts": repetitions, "semantic_fidelity": "partial_winrm"}
