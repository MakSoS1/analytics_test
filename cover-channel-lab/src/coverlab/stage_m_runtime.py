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
    "hypercorn": {"host": "stage-m-asgi.test", "https_port": 9543, "http_port": 9082},
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
    _browser_get("https://stage-m-asgi.test:9543/stage-m/browser-http?" + q, budget_ms=count*max(1, delay_ms)+2500)
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

        time.sleep(min(.02, _gap_seconds(plan, i)))
        req, resp = _direction_sizes(plan["direction_profile"], i); body = _payload(r, plan["payload_profile"], req, i); path = _response_path(resp)
        started = now_iso(); status = _one_http(plan, "POST", base_c2 + path, body)
        events.append({"event_type":"stage_m_dead_drop","phase":"beacon","sent_at":started,"completed_at":now_iso(),"transport":"https","http_method":"POST","http_path":path,"response_status":status,"encoded_length":len(body)})
        if i + 1 < count: time.sleep(_gap_seconds(plan, i))
    return events


def _fallback_campaign(plan: dict, r: random.Random) -> list[dict]:
    count = int(plan["event_count_target"]); first = max(1, min(3, count // 2)); second = max(1, count - first)
    events: list[dict] = []
    order = plan.get("fallback_order", "https_to_dns")
    base, _ = _server_url(plan)
    if order == "https_to_dns":
        for i in range(first):
            started = now_iso(); status = _one_http(plan, "GET", base + "/api/unavailable", None)
            events.append({"event_type":"stage_m_fallback","phase":"primary_https","sent_at":started,"completed_at":now_iso(),"transport":"https","http_method":"GET","http_path":"/api/unavailable","response_status":status,"encoded_length":0})
            if i + 1 < first: time.sleep(min(.02, _gap_seconds(plan, i)))
        dns_plan = {**plan, "family_id":"M-DNS-BEACON", "client_stack":"dnspython", "dns_path": plan.get("dns_path", "recursive_resolver")}
        events.extend({**e, "event_type":"stage_m_fallback", "phase":"fallback_dns"} for e in _dns_campaign(dns_plan, r, second))
    else:
        dns_plan = {**plan, "family_id":"M-DNS-BEACON", "client_stack":"dnspython", "dns_path": plan.get("dns_path", "recursive_resolver")}
        for e in _dns_campaign(dns_plan, r, first): events.append({**e, "event_type":"stage_m_fallback", "phase":"primary_dns"})
        for i in range(second):
            body = _payload(r, plan["payload_profile"], 256, i); started=now_iso(); status=_one_http(plan,"POST",base+"/api/status",body)
            events.append({"event_type":"stage_m_fallback","phase":"fallback_https","sent_at":started,"completed_at":now_iso(),"transport":"https","http_method":"POST","http_path":"/api/status","response_status":status,"encoded_length":len(body)})
            if i + 1 < second: time.sleep(_gap_seconds(plan, i))
    return events


def _python_wss(url: str, count: int, plan: dict, r: random.Random) -> list[int]:
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    replies=[]
    with ws_connect(url, ssl=ctx, open_timeout=10, proxy=None, compression=None) as ws:
        for i in range(count):
            req, resp = _direction_sizes(plan["direction_profile"], i)
            data = base64.b64encode(_payload(r, plan["payload_profile"], min(req, 8192), i)).decode()
            ws.send(json.dumps({"type":"data","conn_id":"m","data":data,"response_bytes":min(resp,8192)},separators=(",",":")))
            reply=ws.recv(); replies.append(len(reply))
            if i + 1 < count: time.sleep(_gap_seconds(plan,i))
    return replies


def _java_wss(url: str, count: int, plan: dict) -> list[int]:
    delay_ms = int(_gap_seconds(plan, 0) * 1000)
    req, resp = _direction_sizes(plan["direction_profile"], 0)
    cp=subprocess.run(["java","-cp",os.environ.get("COVERLAB_JAVA_CLIENT_DIR","/tmp/coverlab-java-client"),"StageMJavaWsClient",url,str(count),str(min(req,8192)),str(min(resp,8192)),str(delay_ms)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=max(30, count * max(1, delay_ms)/1000 + 20))
    if cp.returncode != 0: raise RuntimeError("java websocket failed: "+cp.stderr[-500:])
    data=json.loads(cp.stdout.strip().splitlines()[-1]); return [int(x) for x in data.get("reply_lengths",[])]


def _browser_wss(server: str, count: int, plan: dict) -> list[int]:
    req, resp = _direction_sizes(plan["direction_profile"],0); delay_ms=int(_gap_seconds(plan,0)*1000)
    target="custom" if server=="python_websockets_server" else "hypercorn"
    q=urllib.parse.urlencode({"target":target,"events":count,"payload":min(req,4096),"response":min(resp,4096),"delay_ms":delay_ms})
    _browser_get("https://stage-m-asgi.test:9543/stage-m/browser-wss?"+q, budget_ms=count*max(1,delay_ms)+2500)
    return [resp]*count


def _wss_campaign(plan: dict, r: random.Random) -> list[dict]:
    server=plan["server_stack"]
    url="wss://stage-m-ws.test:9550/ws" if server=="python_websockets_server" else "wss://stage-m-asgi.test:9543/ws"
    count=int(plan["event_count_target"]); started=now_iso()
    if plan["client_stack"]=="python_websockets": replies=_python_wss(url,count,plan,r)
    elif plan["client_stack"]=="java_websocket": replies=_java_wss(url,count,plan)
    else: replies=_browser_wss(server,count,plan)
    base_time=started
    return [{"event_type":"stage_m_wss","sent_at":base_time,"completed_at":now_iso(),"transport":"wss","frame_index":i,"reply_len":replies[i] if i<len(replies) else 0} for i in range(count)]


def _frame_send(sock: socket.socket, framing: str, data: bytes) -> None:
    if framing=="fixed": sock.sendall(struct.pack("!H",len(data))+data)
    elif framing=="length_prefixed": sock.sendall(struct.pack("!I",len(data))+data)
    else: sock.sendall(data.replace(b"\n",b".")+b"\n")


def _frame_recv(sock: socket.socket, framing: str) -> bytes:
    if framing=="line":
        out=b""
        while not out.endswith(b"\n"):
            part=sock.recv(4096)
            if not part: break
            out+=part
        return out.rstrip(b"\n")
    hlen=2 if framing=="fixed" else 4; head=b""
    while len(head)<hlen: head+=sock.recv(hlen-len(head))
    n=struct.unpack("!H" if hlen==2 else "!I",head)[0]; out=b""
    while len(out)<n:
        part=sock.recv(n-len(out))
        if not part: break
        out+=part
    return out


def _python_tunnel(plan: dict, r: random.Random, count: int) -> list[int]:
    framing=plan["framing"]; replies=[]
    with socket.create_connection((TCP_HOST,TCP_PORT),timeout=5) as s:
        _,resp0=_direction_sizes(plan["direction_profile"],0)
        s.sendall(f"STAGEM1 {framing} {min(resp0,8192)}\n".encode()); ack=b""
        while not ack.endswith(b"\n"): ack += s.recv(16)
        if ack.strip()!=b"OK": raise RuntimeError("duplex handshake failed")
        for i in range(count):
            req,_=_direction_sizes(plan["direction_profile"],i); payload=_payload(r,plan["payload_profile"],min(req,8192),i)
            _frame_send(s,framing,payload); replies.append(len(_frame_recv(s,framing)))
            if i+1<count: time.sleep(_gap_seconds(plan,i,burst=True))
    return replies


def _helper_tunnel(plan: dict, count: int, helper: str) -> list[int]:
    req,resp=_direction_sizes(plan["direction_profile"],0); delay_ms=int(_gap_seconds(plan,0,burst=True)*1000)
    if helper=="go": cmd=[os.environ.get("COVERLAB_STAGE_M_GO_TCP","/tmp/coverlab-stage-m-go-tcp"),TCP_HOST,str(TCP_PORT),plan["framing"],str(count),str(min(req,8192)),str(min(resp,8192)),str(delay_ms)]
    else: cmd=["java","-cp",os.environ.get("COVERLAB_JAVA_CLIENT_DIR","/tmp/coverlab-java-client"),"StageMJavaTcpClient",TCP_HOST,str(TCP_PORT),plan["framing"],str(count),str(min(req,8192)),str(min(resp,8192)),str(delay_ms)]
    cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=max(30,count*max(1,delay_ms)/1000+20))
    if cp.returncode!=0: raise RuntimeError(f"{helper} tunnel failed: "+cp.stderr[-500:])
    data=json.loads(cp.stdout.strip().splitlines()[-1]); return [int(x) for x in data.get("reply_lengths",[])]


def _tunnel_campaign(plan: dict, r: random.Random) -> list[dict]:
    count=int(plan["event_count_target"]); started=now_iso()
    if plan["client_stack"]=="python_socket": replies=_python_tunnel(plan,r,count)
    elif plan["client_stack"]=="go_socket": replies=_helper_tunnel(plan,count,"go")
    else: replies=_helper_tunnel(plan,count,"java")
    return [{"event_type":"stage_m_tunnel","sent_at":started,"completed_at":now_iso(),"transport":"tcp","frame_index":i,"reply_len":replies[i] if i<len(replies) else 0,"framing":plan["framing"]} for i in range(count)]


def _run_plan(plan: dict, seed: int) -> list[dict]:
    r=random.Random(seed); family=plan["family_id"]
    if family in {"M-HTTPS-BEACON","M-HTTPS-FRONT","M-HTTPS-LOWENT","M-HTTPS-FRAG","M-HTTP-443","M-RMM-SHAPE"}: return _http_campaign(plan,r)
    if family in {"M-DNS-BEACON","M-DNS-BULK"}: return _dns_campaign(plan,r)
    if family=="M-DOH": return _doh_campaign(plan,r)
    if family=="M-DEAD-DROP": return _dead_drop_campaign(plan,r)
    if family=="M-WSS-LONG": return _wss_campaign(plan,r)
    if family=="M-TUNNEL": return _tunnel_campaign(plan,r)
    if family=="M-FALLBACK": return _fallback_campaign(plan,r)
    raise ValueError(f"unsupported Stage M family: {family}")


def generate_positive_stage(args, manifest: Path, events_out: Path, personas: list[tuple[str,str]]) -> None:
    plan=campaign_plan()
    profile=os.environ.get("COVERLAB_NETEM_PROFILE","clean")
    tier=os.environ.get("COVERLAB_STAGE_M_TIER","all")
    family_filter=os.environ.get("COVERLAB_STAGE_M_FAMILY")
    interval_filter=os.environ.get("COVERLAB_STAGE_M_INTERVAL")
    rows=[x for x in plan if x["network_profile"]==profile and x["campaign_index"]%args.shards==args.shard]
    if tier!="all":
        wanted={"core":"core","diversity":"implementation_diversity","holdout":"implementation_holdout"}.get(tier,tier)
        rows=[x for x in rows if x["tier"]==wanted]
    if family_filter: rows=[x for x in rows if x["family_id"]==family_filter]
    if interval_filter: rows=[x for x in rows if int(x["nominal_interval_seconds"])==int(interval_filter)]
    if os.environ.get("COVERLAB_STAGE_M_SMOKE")=="1":
        seen=set(); smoke=[]
        for x in rows:
            if x["family_id"] not in seen:
                smoke.append(x); seen.add(x["family_id"])
        rows=smoke
    limit=int(os.environ.get("COVERLAB_STAGE_M_LIMIT","0") or 0)
    if limit>0: rows=rows[:limit]
    persona_filter=os.environ.get("COVERLAB_PERSONA_INDEX")
    for row in rows:
        persona_idx=int(row["campaign_index"])%len(personas)
        if persona_filter is not None and int(persona_filter)!=persona_idx: continue
        persona,source_ip=personas[persona_idx]
        seed=args.seed+110_000_000+int(row["campaign_index"])
        _set_state(source_ip,row,seed)
        started=now_iso(); event_rows=_run_plan(row,seed); ended=now_iso()
        family=FAMILY_BY_ID[row["family_id"]]
        dest_ip = RESOLVER_DNS if row.get("dns_path")=="recursive_resolver" else DIRECT_DNS if row["family_id"].startswith("M-DNS-") else "10.20.0.24" if row["family_id"]=="M-HTTP-443" else "10.20.0.21" if row["family_id"]=="M-WSS-LONG" and row["server_stack"]=="python_websockets_server" else "10.20.0.20"
        record={
            "campaign_id":row["campaign_id"],"run_id":"stage-m-positive","scenario_id":row["family_id"],
            "label_binary":1,"label_family":"cover_channel","label_intent":"tunnel" if row["family_id"]=="M-TUNNEL" else "exfil" if row["family_id"]=="M-DNS-BULK" else "c2",
            "benign_semantic_type":None,"protocol":family.transport,"carrier":row["family_id"].lower().replace("m-","").replace("-","_"),
            "attack_mapping":row["attack_mapping"],"visibility_mode":"opaque_and_ground_truth" if family.transport in {"https","wss","multi"} else "content",
            "inspection_policy":"bypass" if family.transport in {"https","wss","multi"} else "not_applicable","inspection_outcome":"encrypted_or_mixed" if family.transport in {"https","wss","multi"} else "plaintext",
            "sni_visibility":"clear","feature_availability_bitmap":"runtime","persona":persona,"source_ip":source_ip,"destination_ip":dest_ip,
            "destination_host":row.get("front_host") if row["family_id"]=="M-HTTPS-FRONT" else TCP_HOST if row["family_id"]=="M-TUNNEL" else "stage-m-local.test",
            "seed":seed,"started_at":started,"ended_at":ended,"expected_events":len(event_rows),"capture_file":args.capture_file,"status":"success",
            "generator_name":"coverlab_stage_m_positive","generator_version":"1.0.0","generator_commit":os.environ.get("GITHUB_SHA",os.environ.get("COVERLAB_GIT_COMMIT","local")),
            "server_impl":row["server_stack"],"client_impl":row["client_stack"],"client_tls_impl":row["client_stack"],"external_dependency":False,"policy_authorized":True,
            "infra_category":"synthetic_local_fixture","plaintext_sha256":hashlib.sha256(f"STAGE_M:{row['campaign_id']}:{seed}".encode()).hexdigest(),
            "experiment_stage":"M_positive_diversity","positive_only":True,"implementation_fidelity":"wire_real_local_safe_fixture",
            "timing_fidelity":"real" if os.environ.get("COVERLAB_STAGE_M_REAL_TIMING")=="1" else "accelerated_nominal_profile",
            "timing_acceleration":1 if os.environ.get("COVERLAB_STAGE_M_REAL_TIMING")=="1" else max(1,int(round(1.0/max(1e-9,float(os.environ.get("COVERLAB_STAGE_M_TIME_SCALE","0.001")))))),
            **{k:v for k,v in row.items() if k not in {"campaign_id","attack_mapping","transport"}},
        }
        _append_json(manifest,record)
        for i,event in enumerate(event_rows):
            event.update({"event_id":f"{row['campaign_id']}-e{i:04d}","campaign_id":row["campaign_id"],"run_id":"stage-m-positive","scenario_id":row["family_id"],"label_binary":1})
            _append_json(events_out,event)
