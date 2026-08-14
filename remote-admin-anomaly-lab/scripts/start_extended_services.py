#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.extended_wire import free_rdp_client, start_group, stop_group, tool, wait_listener  # noqa: E402


def ensure_lab_user() -> None:
    try:
        pwd.getpwnam("adminlab")
    except KeyError:
        subprocess.run(["useradd", "-m", "-s", "/bin/bash", "adminlab"], check=True)
    subprocess.run(
        ["chpasswd"],
        input="adminlab:AdminlabOnly-2026!\n",
        text=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def write_winrm_server(path: Path) -> None:
    path.write_text(
        r'''from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(n)
        marker=b'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'
        if marker not in body:
            self.send_response(400); self.end_headers(); return
        payload=b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><IdentifyResponse/></s:Body></s:Envelope>'
        self.send_response(200)
        self.send_header('Content-Type','application/soap+xml;charset=UTF-8')
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers(); self.wfile.write(payload)
    def log_message(self,*args): pass
HTTPServer(('10.77.0.27',5985),H).serve_forever()
''',
        encoding="utf-8",
    )


def start(state: Path) -> dict:
    if os.geteuid() != 0:
        raise SystemExit("extended service manager requires root")
    state.mkdir(parents=True, exist_ok=True)
    (state / "logs").mkdir(exist_ok=True)
    (state / "pids").mkdir(exist_ok=True)
    ensure_lab_user()

    results: dict[str, dict] = {}
    processes: list[tuple[str, subprocess.Popen[str]]] = []

    vnc = tool("Xtigervnc", "Xvnc")
    if vnc:
        proc = start_group(
            "ra-vnc01",
            [vnc, ":9", "-rfbport", "5900", "-SecurityTypes", "None", "-localhost", "no", "-geometry", "640x480", "-depth", "24"],
            state / "logs/vnc.log",
        )
        processes.append(("vnc", proc))
        results["vnc"] = {"tool": vnc, "listening": wait_listener("ra-vnc01", 5900)}
    else:
        results["vnc"] = {"tool": None, "listening": False}

    xrdp = tool("xrdp")
    rdp_client = free_rdp_client()
    if xrdp and rdp_client:
        Path("/run/xrdp").mkdir(parents=True, exist_ok=True)
        proc = start_group("ra-rdp01", [xrdp, "--nodaemon"], state / "logs/xrdp.log")
        processes.append(("rdp", proc))
        results["rdp"] = {
            "server": xrdp,
            "client": rdp_client,
            "listening": wait_listener("ra-rdp01", 3389),
        }
    else:
        results["rdp"] = {"server": xrdp, "client": rdp_client, "listening": False}

    server = state / "winrm_fixture.py"
    write_winrm_server(server)
    proc = start_group("ra-mgmt01", [sys.executable, str(server)], state / "logs/winrm.log")
    processes.append(("winrm", proc))
    results["winrm"] = {"tool": sys.executable, "listening": wait_listener("ra-mgmt01", 5985)}

    for name, proc in processes:
        (state / f"pids/{name}.pgid").write_text(str(proc.pid) + "\n", encoding="utf-8")
        handle = getattr(proc, "_adminlab_log_handle", None)
        if handle is not None:
            handle.flush()
            handle.close()
            proc._adminlab_log_handle = None  # type: ignore[attr-defined]

    results["ready"] = bool(
        results["vnc"].get("listening")
        and results["rdp"].get("listening")
        and results["winrm"].get("listening")
    )
    (state / "status.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(results, sort_keys=True))
    if not results["ready"]:
        return results
    return results


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
        deadline = time.time() + 2.0
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
        path = args.state / "status.json"
        if not path.is_file():
            raise SystemExit("extended status.json missing")
        status = json.loads(path.read_text(encoding="utf-8"))
        for protocol, port, ns in [("vnc",5900,"ra-vnc01"),("rdp",3389,"ra-rdp01"),("winrm",5985,"ra-mgmt01")]:
            status[protocol]["listening"] = wait_listener(ns, port, seconds=2)
        status["ready"] = all(status[p]["listening"] for p in ("vnc","rdp","winrm"))
        print(json.dumps(status, sort_keys=True))
        return 0 if status["ready"] else 1
    stop(args.state)
    status = start(args.state)
    return 0 if status["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
