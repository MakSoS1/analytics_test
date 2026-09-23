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
