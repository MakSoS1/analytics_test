from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Any

from .manifest import SessionRecord


def run(cmd: list[str], *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, timeout=timeout, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ns_exec(namespace: str, command: list[str], *, timeout: int = 20, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", namespace, *command], timeout=timeout, check=check)


def tool(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def free_rdp_client() -> str | None:
    return tool("xfreerdp3", "xfreerdp", "sdl-freerdp")


def run_rdp_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    """Generate a real FreeRDP -> xrdp negotiation.

    V1 claims Linux RDP wire fidelity only. Authentication/desktop semantics are
    explicitly partial. The downstream PCAP->Zeek mapping gate, not a client
    exit code, proves that a real TCP/RDP flow actually traversed br-adminlab.
    """
    client = free_rdp_client()
    if client is None:
        raise RuntimeError("FreeRDP client unavailable")
    repetitions = 1 if record.label_binary == 0 else 4
    attempts: list[dict[str, Any]] = []
    for _ in range(repetitions):
        cmd = [client, f"/v:{record.dst_ip}:3389", "/u:adminlab", "/p:AdminlabOnly-2026!", "/cert:ignore"]
        if Path(client).name.startswith("xfreerdp"):
            cmd += ["/auth-only", "/timeout:5000"]
        try:
            completed = ns_exec(namespace, cmd, timeout=12, check=False)
            attempts.append({"return_code": completed.returncode, "stderr_tail": completed.stderr[-240:]})
        except subprocess.TimeoutExpired:
            # A timeout after the TCP/RDP negotiation is still valid V1 wire
            # activity. Its existence is independently verified from PCAP.
            attempts.append({"return_code": "timeout", "stderr_tail": ""})
    return {"attempts": repetitions, "client_results": attempts, "semantic_fidelity": "partial_windows", "wire_proof": "pcap_parser_mapping"}


def run_vnc_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    repetitions = 1 if record.label_binary == 0 else 5
    code = r'''import socket,sys
s=socket.create_connection((sys.argv[1],5900),5)
banner=s.recv(12)
assert banner.startswith(b'RFB '),banner
s.sendall(banner)
security=s.recv(64)
assert security,security
s.close()
'''
    for _ in range(repetitions):
        completed = ns_exec(namespace, ["python3", "-c", code, record.dst_ip], timeout=10, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"RFB negotiation failed: {completed.stderr[-400:]}")
    return {"attempts": repetitions, "semantic_fidelity": "partial_client_interaction", "wire_proof": "RFB_banner_and_pcap"}


def run_winrm_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    curl = tool("curl")
    if curl is None:
        raise RuntimeError("curl unavailable for WS-Man fixture")
    repetitions = 1 if record.label_binary == 0 else 5
    soap = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><w:Identify/></s:Body></s:Envelope>')
    for _ in range(repetitions):
        completed = ns_exec(namespace, [curl, "--silent", "--show-error", "--max-time", "5", "-H", "Content-Type: application/soap+xml", "--data", soap, f"http://{record.dst_ip}:5985/wsman"], timeout=10, check=False)
        if completed.returncode != 0 or "IdentifyResponse" not in completed.stdout:
            raise RuntimeError(f"WS-Man fixture failed rc={completed.returncode}: {completed.stderr[-400:]}")
    return {"attempts": repetitions, "semantic_fidelity": "partial_winrm", "wire_proof": "SOAP_response_and_pcap"}
