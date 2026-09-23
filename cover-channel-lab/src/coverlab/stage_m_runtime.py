from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path

import dns.message
import dns.query
import dns.rdatatype
import httpx
from websockets.sync.client import connect as ws_connect

from . import run_campaign as _rc
from .client_runtime_v3 import install as _install_client_runtime
from .stage_m_contract import FAMILY_BY_ID, campaign_plan

_install_client_runtime()

HTTP_ENDPOINTS = {
    "hypercorn": {"host": "stage-m-asgi.test", "https_port": 9443, "http_port": 9082},
    "go_nethttp_server": {"host": "stage-m-go.test", "https_port": 9444, "http_port": 9080},
    "node_http_server": {"host": "stage-m-node.test", "https_port": 9445, "http_port": 9081},
}
DIRECT_DNS = "10.20.0.22"
RESOLVER_DNS = "10.20.0.23"
PLAIN_HTTP_HOST = "plain-http.test"
TCP_HOST = "stage-m-tcp.test"
TCP_PORT = 9090
STATE = Path("/tmp/coverlab_server_state.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _append_json(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")


def _set_state(source_ip: str, plan: dict, seed: int) -> None:
    state = {
        "scenario_id": plan["family_id"],
        "suspicious": True,
        "seed": seed,
        "campaign_id": plan["campaign_id"],
        "stage_m": True,
    }
    lock_path = STATE.with_suffix(STATE.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            raw = json.loads(STATE.read_text()) if STATE.exists() else {"clients": {}, "default": {}}
        except Exception:
            raw = {"clients": {}, "default": {}}
        raw.setdefault("clients", {})[source_ip] = state
        raw["default"] = state
        tmp = STATE.with_suffix(STATE.suffix + ".tmp")
        tmp.write_text(json.dumps(raw)); os.replace(tmp, STATE)
        fcntl.flock(lock, fcntl.LOCK_UN)


def _jitter_multiplier(plan: dict, i: int) -> float:
    jitter = float(plan.get("jitter_fraction", 0.0))
    if jitter <= 0:
        return 1.0
    phase = ((i * 37 + int(plan["campaign_index"]) * 17) % 101) / 100.0
    return max(0.05, 1.0 + (phase * 2.0 - 1.0) * jitter)


def _gap_seconds(plan: dict, i: int, *, burst: bool = False) -> float:
    nominal = float(plan.get("nominal_interval_seconds", 30)) * _jitter_multiplier(plan, i)
    if burst:
        nominal = min(nominal, 2.0)
    if os.environ.get("COVERLAB_STAGE_M_REAL_TIMING") == "1":
        return nominal
    scale = float(os.environ.get("COVERLAB_STAGE_M_TIME_SCALE", "0.001"))
    cap = float(os.environ.get("COVERLAB_STAGE_M_MAX_GAP_SECONDS", "0.15"))
    return max(0.001, min(cap, nominal * scale))


def _payload(r: random.Random, profile: str, size: int, i: int) -> bytes:
    size = max(2, min(65536, int(size)))
    if profile == "short_code":
        raw = (f"id={i%97:02d};ok=1").encode()
        return (raw * ((size // len(raw)) + 1))[:size]
    if profile == "guid":
        raw = str(uuid.UUID(int=r.getrandbits(128))).encode()
        return (raw * ((size // len(raw)) + 1))[:size]
    if profile == "fixed_hex":
        raw = f"{r.getrandbits(32):08x}".encode()
        return (raw * ((size // len(raw)) + 1))[:size]
    if profile == "fragment_2_6":
        n = 2 + (i % 5)
        alphabet = b"abcdefghjkmnpqrstuvwxyz23456789"
        return bytes(alphabet[r.randrange(len(alphabet))] for _ in range(n))
    if profile == "base32_high_entropy":
        raw = bytes(r.randrange(256) for _ in range(max(2, size // 2)))
        return base64.b32encode(raw).rstrip(b"=")[:size]
    return bytes(r.randrange(256) for _ in range(size))


def _direction_sizes(profile: str, i: int) -> tuple[int, int]:
    if profile == "upload_heavy":
        return 4096, 96
    if profile == "download_heavy":
        return 96, 4096
    if profile == "alternating":
        return (4096, 96) if i % 2 == 0 else (96, 4096)
    return 512, 512


def _response_path(response_bytes: int) -> str:
    if response_bytes >= 2048:
        return "/api/detail"
    if response_bytes <= 128:
        return "/api/upload"
    return "/api/status"


def _tls_context(profile: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    if profile == "tls12":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif profile == "tls13" and hasattr(ssl.TLSVersion, "TLSv1_3"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3; ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx


def _browser_get(url: str, budget_ms: int = 1500) -> int:
    chrome = os.environ.get("COVERLAB_CHROME") or next((x for x in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser") if subprocess.run(["bash", "-lc", f"command -v {x}"], stdout=subprocess.DEVNULL).returncode == 0), "")
    if not chrome:
        raise RuntimeError("Chrome/Chromium is required for browser_chromium Stage M profile")
    cp = subprocess.run([
        chrome, "--headless", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
        "--disable-background-networking", "--disable-component-update", "--disable-sync",
        "--metrics-recording-only", "--no-first-run", f"--virtual-time-budget={max(1000, min(30000, int(budget_ms)))}", "--dump-dom", url,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=max(20, min(45, int(budget_ms)/1000 + 15)))
    if cp.returncode != 0:
        raise RuntimeError("browser_chromium failed: " + cp.stderr.decode(errors="replace")[-500:])
    return 200


def _browser_http_campaign(plan: dict) -> list[dict]:
    base, _ = _server_url(plan)
    count = int(plan["event_count_target"]); req, resp = _direction_sizes(plan["direction_profile"], 0)
    family = plan["family_id"]
    path = "/api/status"
    if family == "M-HTTPS-FRAG": path = "/api/items/a1?page=1"
    elif family == "M-RMM-SHAPE": path = "/api/status"
    else: path = _response_path(resp)
    delay_ms = int(_gap_seconds(plan, 0, burst=family == "M-RMM-SHAPE") * 1000)
    q = urllib.parse.urlencode({"target": base + path, "events": count, "payload": min(req, 4096), "delay_ms": delay_ms, "method": "GET" if family == "M-HTTPS-FRAG" else "POST"})
    _browser_get("https://stage-m-asgi.test:9443/stage-m/browser-http?" + q, budget_ms=count*max(1, delay_ms)+2500)
    return [{"event_type":"stage_m_http","sent_at":now_iso(),"completed_at":now_iso(),"transport":"https","http_method":"GET" if family=="M-HTTPS-FRAG" else "POST","http_path":path,"response_status":200,"encoded_length":0 if family=="M-HTTPS-FRAG" else min(req,4096),"response_bytes_target":resp} for _ in range(count)]

def _server_url(plan: dict, *, force_host: str | None = None, plaintext: bool = False) -> tuple[str, bool]:
    if plan["family_id"] == "M-HTTP-443":
        port = 443 if int(plan["campaign_index"]) % 2 == 0 else 80
        return f"http://{PLAIN_HTTP_HOST}:{port}", False
    ep = HTTP_ENDPOINTS[plan["server_stack"]]
    host = force_host or (plan["front_host"] if plan["family_id"] == "M-HTTPS-FRONT" else ep["host"])
    if plaintext:
        return f"http://{host}:{ep['http_port']}", False
    return f"https://{host}:{ep['https_port']}", plan["client_stack"] == "python_httpx_h2"


def _one_http(plan: dict, method: str, url: str, body: bytes | None, *, persistent: httpx.Client | None = None) -> int:
    headers = {"Accept": "application/octet-stream", "User-Agent": "Mozilla/5.0" if plan["client_stack"] == "browser_chromium" else "stage-m-client/1.0"}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    if plan["client_stack"] == "browser_chromium":
        return _browser_get(url)
    if persistent is not None:
        resp = persistent.request(method, url, headers=headers, content=body); _ = resp.content; return int(resp.status_code)
    status, _ = _rc.execute_http(plan["client_stack"], method, url, headers, body, bool(plan["client_stack"] == "python_httpx_h2"))
    return int(status)


def _http_campaign(plan: dict, r: random.Random) -> list[dict]:
    if plan["client_stack"] == "browser_chromium":
        return _browser_http_campaign(plan)
    base, use_h2 = _server_url(plan)
    count = int(plan["event_count_target"])
    events: list[dict] = []
    persistent = None
    if plan.get("connection_mode") == "keepalive" and plan["client_stack"] in {"python_httpx", "python_httpx_h2"}:
        persistent = httpx.Client(verify=_tls_context(plan.get("tls_profile", "native")), http2=use_h2, timeout=15, follow_redirects=False, trust_env=False)
    try:
        for i in range(count):
            req_size, resp_size = _direction_sizes(plan["direction_profile"], i)
            family = plan["family_id"]
            path = _response_path(resp_size)
            method = "POST"
            body = _payload(r, plan["payload_profile"], req_size, i)
            if family == "M-HTTPS-FRAG":
                frag = urllib.parse.quote(_payload(r, "fragment_2_6", 6, i).decode(errors="ignore"))
                path = f"/api/items/{frag}?page={i%7+1}"; method = "GET"; body = None
            elif family == "M-HTTPS-LOWENT":
                body = _payload(r, plan["payload_profile"], min(128, req_size), i)
            elif family == "M-RMM-SHAPE":
                poll_phase = i < max(1, int(count * 0.7))
                if poll_phase:
                    method = "GET"; body = None; path = "/api/status"
                else:
                    path = "/api/detail" if i % 2 else "/api/upload"
                    body = _payload(r, "short_code", 128 if i % 2 else 1024, i)
            started = now_iso()
            status = _one_http(plan, method, base + path, body, persistent=persistent)
            events.append({
                "event_type": "stage_m_http", "sent_at": started, "completed_at": now_iso(),
                "transport": "https" if base.startswith("https://") else "http", "http_method": method,
                "http_path": path, "response_status": status, "encoded_length": len(body or b""),
                "response_bytes_target": resp_size,
            })
            if i + 1 < count:
                time.sleep(_gap_seconds(plan, i, burst=(family == "M-RMM-SHAPE" and i >= int(count * .7))))
    finally:
        if persistent is not None:
            persistent.close()
    return events


def _dns_name(plan: dict, r: random.Random, i: int) -> str:
    profile = plan["payload_profile"]
    if plan["family_id"] == "M-DNS-BULK":
        raw = _payload(r, profile, 48, i).decode(errors="ignore").lower().replace("=", "")[:55]
    else:
        raw = _payload(r, profile, 24, i).decode(errors="ignore").lower().replace("=", "")[:40]
    raw = "".join(c if c.isalnum() or c == "-" else "a" for c in raw) or "x"
    bucket = (i * 37 + int(plan.get("campaign_index", 0)) * 17) % 100
    nx = "nx." if bucket < int(float(plan.get("dns_nxdomain_ratio", 0)) * 100) else ""
    return f"{raw}.{nx}m{i%17}.stage-m.test."


def _dns_query_once(plan: dict, name: str, qtype: str) -> tuple[int, int]:
    target = RESOLVER_DNS if plan.get("dns_path") == "recursive_resolver" else DIRECT_DNS
    q = dns.message.make_query(name, qtype)
    transport = plan.get("dns_transport", "udp")
    client = plan["client_stack"]
    if client == "dig":
        cmd = ["dig", f"@{target}", "-p", "53", name, qtype, "+time=2", "+tries=1", "+noall", "+comments"]
        if transport == "tcp": cmd.append("+tcp")
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if cp.returncode != 0: raise RuntimeError("dig failed: " + cp.stderr.decode(errors="replace")[-300:])
        text = cp.stdout.decode(errors="replace")
        rcode = 3 if "status: NXDOMAIN" in text else (0 if "status: NOERROR" in text else 2)
        return rcode, len(text)
    if client == "raw_socket":
        wire = q.to_wire()
        if transport == "tcp":
            with socket.create_connection((target, 53), timeout=3) as s:
                s.sendall(struct.pack("!H", len(wire)) + wire)
                head = s.recv(2)
                if len(head) != 2: raise RuntimeError("short DNS TCP response")
                n = struct.unpack("!H", head)[0]; data = b""
                while len(data) < n:
                    part = s.recv(n - len(data))
                    if not part: break
                    data += part
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3); s.sendto(wire, (target, 53)); data, _ = s.recvfrom(65535)
        resp = dns.message.from_wire(data); return int(resp.rcode()), len(data)
    resp = dns.query.tcp(q, target, timeout=3) if transport == "tcp" else dns.query.udp(q, target, timeout=3)
    return int(resp.rcode()), len(resp.to_wire())


def _dns_campaign(plan: dict, r: random.Random, count: int | None = None) -> list[dict]:
    count = int(count or plan["event_count_target"]); events = []
    for i in range(count):
        name = _dns_name(plan, r, i); qtype = plan.get("dns_qtype", "TXT")
        started = now_iso(); rcode, n = _dns_query_once(plan, name, qtype)
        events.append({"event_type": "stage_m_dns", "sent_at": started, "completed_at": now_iso(), "transport": f"dns_{plan.get('dns_transport','udp')}", "dns_qname": name, "dns_qtype": qtype, "dns_rcode": rcode, "response_length": n})
        if i + 1 < count:
            if plan["family_id"] == "M-DNS-BULK": time.sleep(0.001)
            else: time.sleep(_gap_seconds(plan, i))
    return events


def _doh_campaign(plan: dict, r: random.Random) -> list[dict]:
    base, use_h2 = _server_url(plan, force_host="front-resolver.test")
    count = int(plan["event_count_target"]); events = []
    method = plan.get("doh_method", "POST")
    persistent = None
    if plan.get("connection_mode") == "keepalive" and plan["client_stack"] in {"python_httpx", "python_httpx_h2"}:
        persistent = httpx.Client(verify=_tls_context(plan.get("tls_profile", "native")), http2=use_h2, timeout=15, trust_env=False)
    try:
        for i in range(count):
            qname = _dns_name({**plan, "family_id": "M-DNS-BEACON"}, r, i)
            wire = dns.message.make_query(qname, plan.get("dns_qtype", "TXT")).to_wire()
            if method == "GET":
                token = base64.urlsafe_b64encode(wire).decode().rstrip("=")
                url = base + "/dns-query?dns=" + urllib.parse.quote(token); body = None
            else:
                url = base + "/dns-query"; body = wire
            started = now_iso()
            if persistent is not None:
                headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
                resp = persistent.request(method, url, headers=headers, content=body); _ = resp.content; status = int(resp.status_code)
            else:
                headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
                status, _ = _rc.execute_http(plan["client_stack"], method, url, headers, body, use_h2)
            events.append({"event_type": "stage_m_doh", "sent_at": started, "completed_at": now_iso(), "transport": "doh", "http_method": method, "http_path": "/dns-query", "response_status": int(status), "encoded_length": len(wire), "dns_qname": qname})
            if i + 1 < count: time.sleep(_gap_seconds(plan, i))
    finally:
        if persistent is not None: persistent.close()
    return events


def _dead_drop_campaign(plan: dict, r: random.Random) -> list[dict]:
    count = int(plan["event_count_target"]); events = []
    base_front, _ = _server_url(plan, force_host=plan["front_host"])
    base_c2, _ = _server_url(plan, force_host=HTTP_ENDPOINTS[plan["server_stack"]]["host"])
    for i in range(count):
        started = now_iso(); status = _one_http(plan, "GET", base_front + f"/public/bootstrap-{i%3}.json", None)
        events.append({"event_type":"stage_m_dead_drop","phase":"dead_drop","sent_at":started,"completed_at":now_iso(),"transport":"https","http_method":"GET","http_path":f"/public/bootstrap-{i%3}.json","response_status":status,"encoded_length":0})
