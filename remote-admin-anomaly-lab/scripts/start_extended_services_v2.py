#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pwd
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.extended_wire import free_rdp_client, start_group, tool, wait_listener  # noqa: E402


def ensure_lab_user() -> None:
    try:
        pwd.getpwnam("adminlab")
    except KeyError:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", "adminlab"], check=True)
    subprocess.run(["chpasswd"], input="adminlab:AdminlabOnly-2026!\n", text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write_winrm_server(path: Path) -> None:
    path.write_text(r'''from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0')); body=self.rfile.read(n)
        if b'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd' not in body:
            self.send_response(400); self.end_headers(); return
        payload=b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><IdentifyResponse/></s:Body></s:Envelope>'
        self.send_response(200); self.send_header('Content-Type','application/soap+xml;charset=UTF-8'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def log_message(self,*args): pass
HTTPServer(('10.77.0.27',5985),H).serve_forever()
''', encoding="utf-8")


def persist_process(state: Path, name: str, proc: subprocess.Popen[str]) -> None:
    (state / "pids").mkdir(parents=True, exist_ok=True)
    (state / f"pids/{name}.pgid").write_text(str(proc.pid) + "\n", encoding="utf-8")
    handle = getattr(proc, "_adminlab_log_handle", None)
    if handle is not None:
        handle.flush()
        handle.close()
        proc._adminlab_log_handle = None  # type: ignore[attr-defined]


def stop(state: Path) -> None:
    if not state.exists():
        return
    for pgfile in sorted((state / "pids").glob("*.pgid")):
        raw = pgfile.read_text(encoding="utf-8").strip()
        if not raw.isdigit():
            continue
        pgid = int(raw)
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        pgfile.unlink(missing_ok=True)


def start(state: Path) -> dict:
    stop(state)
    state.mkdir(parents=True, exist_ok=True)
    (state / "logs").mkdir(exist_ok=True)
    ensure_lab_user()
    results: dict[str, dict] = {}

    vnc = tool("Xtigervnc", "Xvnc")
    if not vnc:
        raise RuntimeError("TigerVNC server unavailable")
    vnc_proc = start_group("ra-vnc01", [vnc, ":9", "-rfbport", "5900", "-SecurityTypes", "None", "-localhost", "no", "-geometry", "640x480", "-depth", "24"], state / "logs/vnc.log")
    persist_process(state, "vnc", vnc_proc)
    results["vnc"] = {"tool": vnc, "listening_5900": wait_listener("ra-vnc01", 5900, seconds=8)}

    xrdp = tool("xrdp")
    sesman = tool("xrdp-sesman")
    client = free_rdp_client()
    if not xrdp or not sesman or not client:
        raise RuntimeError(f"RDP stack incomplete xrdp={xrdp} sesman={sesman} client={client}")
    Path("/run/xrdp").mkdir(parents=True, exist_ok=True)
    for stale in (Path("/run/xrdp/xrdp.pid"), Path("/run/xrdp/xrdp-sesman.pid")):
        stale.unlink(missing_ok=True)
    sesman_proc = start_group("ra-rdp01", [sesman, "--nodaemon"], state / "logs/xrdp-sesman.log")
    persist_process(state, "xrdp-sesman", sesman_proc)
    sesman_ready = wait_listener("ra-rdp01", 3350, seconds=8)
    if not sesman_ready:
        raise RuntimeError("xrdp-sesman did not listen on namespace loopback/TCP 3350")
    xrdp_proc = start_group("ra-rdp01", [xrdp, "--nodaemon"], state / "logs/xrdp.log")
    persist_process(state, "xrdp", xrdp_proc)
    rdp_ready = wait_listener("ra-rdp01", 3389, seconds=8)
    results["rdp"] = {"server": xrdp, "sesman": sesman, "client": client, "listening_3350": sesman_ready, "listening_3389": rdp_ready}

    winrm = state / "winrm_fixture.py"
    write_winrm_server(winrm)
    winrm_proc = start_group("ra-mgmt01", [sys.executable, str(winrm)], state / "logs/winrm.log")
    persist_process(state, "winrm", winrm_proc)
    results["winrm"] = {"listening_5985": wait_listener("ra-mgmt01", 5985, seconds=8)}

    results["ready"] = bool(results["vnc"]["listening_5900"] and results["rdp"]["listening_3350"] and results["rdp"]["listening_3389"] and results["winrm"]["listening_5985"])
    (state / "status.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(results, sort_keys=True))
    if not results["ready"]:
        raise RuntimeError(f"extended service readiness failed: {results}")
    return results


def verify(state: Path) -> bool:
    status = json.loads((state / "status.json").read_text(encoding="utf-8"))
    checks = {
        "vnc": wait_listener("ra-vnc01", 5900, seconds=2),
        "sesman": wait_listener("ra-rdp01", 3350, seconds=2),
        "rdp": wait_listener("ra-rdp01", 3389, seconds=2),
        "winrm": wait_listener("ra-mgmt01", 5985, seconds=2),
    }
    print(json.dumps({"stored": status, "live": checks}, sort_keys=True))
    return all(checks.values())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["start", "verify", "stop"])
    parser.add_argument("state", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("extended service manager requires root")
    if args.mode == "stop":
        stop(args.state)
        return 0
    if args.mode == "verify":
        return 0 if verify(args.state) else 1
    start(args.state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
