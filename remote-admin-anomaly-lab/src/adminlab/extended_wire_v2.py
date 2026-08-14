from __future__ import annotations

import shutil
import struct
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


def _attempts(record: SessionRecord) -> int:
    return max(1, int(record.wire_attempts))


def run_rdp_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    """Generate a real FreeRDP -> xrdp credential negotiation/session attempt.

    V1 still classifies Linux xrdp as partial Windows semantic fidelity. A
    client return code alone is never accepted as proof: downstream PCAP/Zeek
    mapping must independently observe the RDP flow.
    """
    client = free_rdp_client()
    if client is None:
        raise RuntimeError("FreeRDP client unavailable")
    repetitions = _attempts(record)
    attempts: list[dict[str, Any]] = []
    for _ in range(repetitions):
        cmd = [client, f"/v:{record.dst_ip}:3389", "/u:adminlab", "/p:AdminlabOnly-2026!", "/cert:ignore"]
        # auth-only is used on the hosted Linux fixture because a graphical
        # Windows desktop is not available. Native Windows RDP remains a
        # separate fidelity/challenge corpus.
        if Path(client).name.startswith("xfreerdp"):
            cmd += ["/auth-only", "/timeout:5000"]
        try:
            completed = ns_exec(namespace, cmd, timeout=12, check=False)
            attempts.append({"return_code": completed.returncode, "stderr_tail": completed.stderr[-240:]})
        except subprocess.TimeoutExpired:
            attempts.append({"return_code": "timeout", "stderr_tail": ""})
    return {
        "attempts": repetitions,
        "client_results": attempts,
        "semantic_fidelity": "partial_windows",
        "wire_proof": "pcap_parser_mapping",
    }


def run_vnc_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    """Run a minimal but interactive RFB 3.8 client against real TigerVNC.

    Unlike the old banner-only probe this completes security negotiation,
    ClientInit/ServerInit, requests framebuffer data, and sends key/pointer
    events. It remains a minimal client implementation rather than a GUI viewer,
    so semantic fidelity is explicitly not labelled "high".
    """
    repetitions = _attempts(record)
    code = r'''import socket,struct,sys
host=sys.argv[1]
s=socket.create_connection((host,5900),5)
s.settimeout(5)
version=s.recv(12)
assert version.startswith(b'RFB '),version
s.sendall(b'RFB 003.008\n')
n=s.recv(1)
assert n and n[0]>0,n
security=s.recv(n[0])
assert 1 in security,security
s.sendall(b'\x01')
result=s.recv(4)
assert len(result)==4 and struct.unpack('>I',result)[0]==0,result
# Shared ClientInit
s.sendall(b'\x01')
header=b''
while len(header)<24:
    chunk=s.recv(24-len(header))
    if not chunk: raise RuntimeError('short ServerInit')
    header+=chunk
w,h=struct.unpack('>HH',header[:4])
name_len=struct.unpack('>I',header[20:24])[0]
name=b''
while len(name)<name_len:
    name+=s.recv(name_len-len(name))
# Request Raw encoding.
s.sendall(struct.pack('>BBH',2,0,1)+struct.pack('>i',0))
# Non-incremental framebuffer request over a bounded rectangle.
rw=max(1,min(w,64)); rh=max(1,min(h,64))
s.sendall(struct.pack('>BBHHHH',3,0,0,0,rw,rh))
# Real input events: key down/up and pointer movement/click.
s.sendall(struct.pack('>BBHI',4,1,0,0x61))
s.sendall(struct.pack('>BBHI',4,0,0,0x61))
s.sendall(struct.pack('>BBHH',5,0,min(10,w-1),min(10,h-1)))
s.sendall(struct.pack('>BBHH',5,1,min(10,w-1),min(10,h-1)))
s.sendall(struct.pack('>BBHH',5,0,min(10,w-1),min(10,h-1)))
# Read enough to prove a server message arrived after the update request.
msg=s.recv(1)
assert msg,msg
s.close()
print('interactive_rfb_ok',w,h,name[:80])
'''
    results: list[str] = []
    for _ in range(repetitions):
        completed = ns_exec(namespace, ["python3", "-c", code, record.dst_ip], timeout=12, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"interactive RFB session failed: {completed.stderr[-500:]}")
        results.append(completed.stdout[-240:])
    return {
        "attempts": repetitions,
        "semantic_fidelity": "interactive_minimal_client",
        "wire_proof": "RFB_security_serverinit_framebuffer_input_and_pcap",
        "client_results": results,
    }


def run_winrm_session(record: SessionRecord, namespace: str) -> dict[str, Any]:
    curl = tool("curl")
    if curl is None:
        raise RuntimeError("curl unavailable for WS-Man fixture")
    repetitions = _attempts(record)
    soap = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><w:Identify/></s:Body></s:Envelope>')
    for _ in range(repetitions):
        completed = ns_exec(namespace, [curl, "--silent", "--show-error", "--max-time", "5", "-H", "Content-Type: application/soap+xml", "--data", soap, f"http://{record.dst_ip}:5985/wsman"], timeout=10, check=False)
        if completed.returncode != 0 or "IdentifyResponse" not in completed.stdout:
            raise RuntimeError(f"WS-Man fixture failed rc={completed.returncode}: {completed.stderr[-400:]}")
    return {"attempts": repetitions, "semantic_fidelity": "partial_winrm", "wire_proof": "SOAP_response_and_pcap"}
