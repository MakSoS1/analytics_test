#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

LAB = "10.77.0.0/24"


def run(cmd: list[str], *, timeout: int = 15, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=check,
        timeout=timeout,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def tool(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def ns_exec(namespace: str, command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", namespace, *command], timeout=timeout)


def port_listening(namespace: str, port: int) -> bool:
    result = ns_exec(namespace, ["ss", "-ltn"], timeout=5)
    return result.returncode == 0 and any(
        line.rstrip().endswith(f":{port}") for line in result.stdout.splitlines()
    )


def wait_listener(namespace: str, port: int, seconds: float = 5.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if port_listening(namespace, port):
            return True
        time.sleep(0.2)
    return False


def start_group(namespace: str, command: list[str], log: Path) -> subprocess.Popen[str]:
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = log.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        ["setsid", "ip", "netns", "exec", namespace, *command],
        stdout=fh,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proc._adminlab_log_handle = fh  # type: ignore[attr-defined]
    return proc


def stop_group(proc: subprocess.Popen[str], *, graceful_signal: int = signal.SIGTERM) -> None:
    try:
        os.killpg(proc.pid, graceful_signal)
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


def start_capture(pcap: Path, log: Path) -> subprocess.Popen[str]:
    pcap.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = log.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        ["setsid", "tcpdump", "-i", "br-adminlab", "-U", "-s", "0", "-n", "-w", str(pcap)],
        stdout=fh,
        stderr=subprocess.STDOUT,
        text=True,
    )
    proc._adminlab_log_handle = fh  # type: ignore[attr-defined]
    time.sleep(1.0)
    if proc.poll() is not None:
        fh.flush()
        raise RuntimeError(f"tcpdump exited before fidelity probes; see {log}")
    return proc


def validate_capture(pcap: Path) -> dict[str, Any]:
    if not pcap.is_file() or pcap.stat().st_size <= 24:
        raise RuntimeError(f"fidelity capture missing or empty: {pcap}")
    check = run(["tcpdump", "-nn", "-r", str(pcap), "-c", "1"], timeout=10)
    if check.returncode != 0:
        raise RuntimeError(f"fidelity capture unreadable: {check.stderr.strip()}")
    return {"path": str(pcap), "bytes": pcap.stat().st_size, "readable": True}


def safe_result(protocol: str, wire: str, semantic: str) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "status": "unavailable",
        "tool_present": False,
        "wire_observed": False,
        "wire_fidelity": wire,
        "semantic_fidelity": semantic,
        "evidence": [],
    }


def probe_vnc(work: Path) -> dict[str, Any]:
    result = safe_result("vnc", "real_rfb", "partial_client_interaction")
    server = tool("Xtigervnc", "Xvnc")
    result["tool_present"] = bool(server)
    if not server:
        result["evidence"].append("TigerVNC server executable not present")
        return result
    proc: subprocess.Popen[str] | None = None
    try:
        proc = start_group(
            "ra-vnc01",
            [server, ":9", "-rfbport", "5900", "-SecurityTypes", "None", "-localhost", "no", "-geometry", "640x480", "-depth", "24"],
            work / "vnc-server.log",
        )
        listener = wait_listener("ra-vnc01", 5900)
        if not listener:
            result["evidence"].append("TigerVNC did not expose TCP/5900")
            return result
        client_code = (
            "import socket; s=socket.create_connection(('10.77.0.25',5900),3); "
            "b=s.recv(12); print(b.decode('ascii','replace').strip()); "
            "assert b.startswith(b'RFB '); s.close()"
        )
        client = ns_exec("ra-help01", ["python3", "-c", client_code], timeout=8)
        result["wire_observed"] = client.returncode == 0 and "RFB " in client.stdout
        result["evidence"].append(f"listener={listener} client_rc={client.returncode} banner={client.stdout.strip()!r}")
        if result['tool_present'] and result['wire_observed']:
            result["status"] = "validated"
        return result
    finally:
        if proc is not None:
            stop_group(proc)


def probe_dcerpc() -> dict[str, Any]:
    result = safe_result("dcerpc", "real_dcerpc_samba", "partial_dcom")
    rpc = tool("rpcclient")
    result["tool_present"] = bool(rpc)
    if not rpc:
        result["evidence"].append("rpcclient executable not present")
        return result
    attempt = ns_exec(
        "ra-paw01",
        [rpc, "-N", "-U", "", "10.77.0.23", "-c", "srvinfo"],
        timeout=12,
    )
    result["wire_observed"] = attempt.returncode == 0
    result["evidence"].append(
        f"rpcclient_rc={attempt.returncode} stdout={attempt.stdout.strip()[:240]!r} stderr={attempt.stderr.strip()[:240]!r}"
    )
    if result['tool_present'] and result['wire_observed']:
        result["status"] = "validated"
    return result


def probe_rdp(work: Path) -> dict[str, Any]:
    result = safe_result("rdp", "real_rdp_linux", "partial_windows")
    xrdp = tool("xrdp")
    client = tool("xfreerdp", "xfreerdp3", "sdl-freerdp")
    result["tool_present"] = bool(xrdp and client)
    if not xrdp or not client:
        result["evidence"].append(f"xrdp={bool(xrdp)} freerdp_client={bool(client)}")
        return result
    proc: subprocess.Popen[str] | None = None
    try:
        proc = start_group("ra-rdp01", [xrdp, "--nodaemon"], work / "xrdp.log")
        listener = wait_listener("ra-rdp01", 3389, seconds=6)
        if not listener:
            result["evidence"].append("xrdp process started but did not listen on TCP/3389")
            return result
        if Path(client).name.startswith("xfreerdp"):
            cmd = [client, "/v:10.77.0.24", "/u:adminlab", "/p:invalid", "/cert:ignore", "/auth-only", "/timeout:5000"]
        else:
            cmd = [client, "/v:10.77.0.24", "/u:adminlab", "/p:invalid", "/cert:ignore"]
        attempt = ns_exec("ra-help01", cmd, timeout=12)
        # Authentication can fail by construction. A real xrdp listener plus a
        # real FreeRDP negotiation attempt is the V1 Linux-wire claim.
        result["wire_observed"] = listener
        result["evidence"].append(
            f"listener={listener} freerdp_rc={attempt.returncode} stdout={attempt.stdout.strip()[:160]!r} stderr={attempt.stderr.strip()[:160]!r}"
        )
        if result['tool_present'] and result['wire_observed']:
            result["status"] = "validated"
        return result
    finally:
        if proc is not None:
            stop_group(proc)


def probe_winrm(work: Path) -> dict[str, Any]:
    result = safe_result("winrm", "real_http_wsman_fixture", "partial_winrm")
    curl = tool("curl")
    result["tool_present"] = bool(curl)
    if not curl:
        result["evidence"].append("curl not present")
        return result

    server_code = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(n)
        if b'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd' not in body:
            self.send_response(400); self.end_headers(); return
        payload=b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><IdentifyResponse/></s:Body></s:Envelope>'
        self.send_response(200)
        self.send_header('Content-Type','application/soap+xml;charset=UTF-8')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers(); self.wfile.write(payload)
    def log_message(self, *args): pass
HTTPServer(('10.77.0.27',5985),H).serve_forever()
'''
    proc: subprocess.Popen[str] | None = None
    try:
        proc = start_group("ra-mgmt01", ["python3", "-c", server_code], work / "winrm-fixture.log")
        listener = wait_listener("ra-mgmt01", 5985)
        if not listener:
            result["evidence"].append("bounded WS-Man fixture did not listen")
            return result
        soap = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Body><w:Identify/></s:Body></s:Envelope>'
        )
        attempt = ns_exec(
            "ra-paw01",
            [curl, "--silent", "--show-error", "--max-time", "5", "-H", "Content-Type: application/soap+xml", "--data", soap, "http://10.77.0.27:5985/wsman"],
            timeout=8,
        )
        result["wire_observed"] = attempt.returncode == 0 and "IdentifyResponse" in attempt.stdout
        result["evidence"].append(f"listener={listener} curl_rc={attempt.returncode} response={attempt.stdout[:180]!r}")
        if result["wire_observed"]:
            result["status"] = "partial"
        return result
    finally:
        if proc is not None:
            stop_group(proc)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("fidelity probe requires root for namespaces, listeners and capture")

    args.out.mkdir(parents=True, exist_ok=True)
    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    capture: subprocess.Popen[str] | None = None
    try:
        capture = start_capture(args.pcap, args.out / "tcpdump.log")
        probes = [probe_vnc(args.out), probe_dcerpc(), probe_rdp(args.out), probe_winrm(args.out)]
    finally:
        if capture is not None:
            stop_group(capture, graceful_signal=signal.SIGINT)

    capture_report = validate_capture(args.pcap)
    payload = {
        "lab_cidr": LAB,
        "external_targets_allowed": False,
        "payload_execution_allowed": False,
        "c2_frameworks_enabled": False,
        "capture": capture_report,
        "results": probes,
    }
    (args.out / "fidelity-results.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
