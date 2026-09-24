from __future__ import annotations

"""Stage M: positive-only cover-channel shape corpus.

This module generates local, bounded, synthetic network traffic for defensive NDR
research. It never executes commands, forwards arbitrary traffic, reaches the
Internet, or implements post-exploitation behavior.

The unit of diversity is:
  channel family x client stack x local server/front stack x network profile
rather than repeated seeds of one generator implementation.
"""

import argparse
import asyncio
import base64
import fcntl
import hashlib
import json
import math
import os
import random
import socket
import ssl
import subprocess
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import dns.message
import dns.name
import dns.rdatatype
import grpc
import paho.mqtt.client as mqtt
from websockets.sync.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, WebSocketException
from aioquic.asyncio.client import connect as quic_connect
from aioquic.quic.configuration import QuicConfiguration

from . import run_campaign as rc
from .client_runtime_v3 import install as install_client_runtime
from .doq_fixture import DOQ_ALPN, DoQClientProtocol
from .h3_fixture import LabH3Client
from aioquic.h3.connection import H3_ALPN

install_client_runtime()

PERSONAS = (
    ("Victim-1-Office", "10.20.0.10"),
    ("Victim-2-Dev", "10.20.0.11"),
    ("Persona-DevOps", "10.20.0.30"),
    ("Persona-SOC-Analyst", "10.20.0.31"),
)

# All targets are local .test aliases in the isolated namespace.
HTTPS_DIRECT = ("cover-api.test", "cover-h2.test")
HTTPS_FRONTS = (
    "edge-front.test", "cdn-front.test", "workers-front.test",
    "graph-front.test", "telegram-front.test", "resolver-front.test",
)
WSS_DIRECT = "cover-ws.test"
WSS_FRONT = "edge-ws.test"
DNS_AUTH = "10.20.0.20"
DNS_RECURSOR = "10.20.0.23"

HTTP_CLIENTS = (
    "python_httpx", "python_httpx_h2", "python_stdlib", "curl_linux",
    "go_nethttp", "node_fetch", "java_httpclient", "rust_reqwest", "browser_chromium",
)
WSS_CLIENTS = ("python_websockets", "node_websocket", "chromium_websocket")
NETEM_PROFILES = ("clean", "wan_20ms", "wan_80ms", "lossy_wifi", "constrained")
INTERVALS = (5, 30, 120, 300, 1200, 3600)
JITTERS = (0.00, 0.05, 0.15, 0.30, 0.50)
EVENT_COUNTS = (3, 5, 10, 20, 50, 100)
VOLUME_MODES = ("rare_beacon", "interactive", "trickle", "bulk")
ASYMMETRY = ("small_small", "small_large", "large_small", "upload_heavy", "download_heavy", "symmetric")
PAYLOAD_MODES = ("high_entropy", "low_entropy", "fragment_2_6")

# Expanded P0/P1 positive-corpus budget: 13,350 campaigns.
FAMILY_COUNTS = {
    # P0/P1 positive-only target. Existing V5 H3 / extended protocol shards stay
    # separate and are not re-generated here merely to inflate volume.
    "M-HTTPS-BEACON": 1500,
    "M-HTTPS-FRONT": 600,
    "M-HTTPS-LOWENT": 400,
    "M-HTTPS-FRAG": 400,
    "M-HTTP-443": 250,
    "M-DNS-BEACON": 750,
    "M-DNS-BULK": 750,
    "M-DOH": 800,
    "M-DOQ": 800,
    "M-H3-QUIC": 800,
    "M-DEAD-DROP": 300,
    "M-WSS-LONG": 800,
    "M-TUNNEL": 600,
    "M-FALLBACK": 600,
    "M-CLOUD-API": 1500,
    "M-TIMING-XCARRIER": 2000,
    "M-PUBSUB-MQTT": 500,
    "M-GRPC-BIDI": 400,
    "M-RMM-SHAPE": 400,
}

ATTACK_MAPPING = {
    "M-HTTPS-BEACON": ["T1071.001", "T1573"],
    "M-HTTPS-FRONT": ["T1071.001", "T1102", "T1090"],
    "M-HTTPS-LOWENT": ["T1071.001", "T1001.001"],
    "M-HTTPS-FRAG": ["T1071.001", "T1001.001"],
    "M-HTTP-443": ["T1071.001"],
    "M-DNS-BEACON": ["T1071.004"],
    "M-DNS-BULK": ["T1071.004", "T1041"],
    "M-DOH": ["T1071.001", "T1071.004"],
    "M-DOQ": ["T1071.004", "T1573"],
    "M-H3-QUIC": ["T1071.001", "T1573"],
    "M-CLOUD-API": ["T1102", "T1071.001"],
    "M-TIMING-XCARRIER": ["T1071", "T1001"],
    "M-PUBSUB-MQTT": ["T1071.005"],
    "M-GRPC-BIDI": ["T1071.001", "T1572"],
    "M-DEAD-DROP": ["T1102.001", "T1071.001"],
    "M-WSS-LONG": ["T1071.001", "T1573"],
    "M-TUNNEL": ["T1572", "T1090"],
    "M-FALLBACK": ["T1071.001", "T1071.004"],
    "M-RMM-SHAPE": ["T1219", "T1071.001"],
}


@dataclass(frozen=True)
class CampaignSpec:
    index: int
    family: str
    family_index: int
    implementation_id: str
    client_impl: str
    server_impl: str
    front_host: str
    network_topology: str
    interval_seconds: float
    interval_bucket_seconds: int
    jitter_fraction: float
    event_count: int
    event_count_bucket: int
    volume_mode: str
    asymmetry: str
    payload_mode: str
    holdout_fold: int


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stable_mod(text: str, n: int) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest()[:12], 16) % n


def implementation_catalog(family: str) -> tuple[tuple[str, str, str, str], ...]:
    """Return (implementation_id, client, server, topology/front)."""
    if family in {"M-DNS-BEACON", "M-DNS-BULK"}:
        return (
            ("dns-python-auth-udp", "python_dnspython_udp", "local_authoritative", "direct_authoritative"),
            ("dns-python-auth-tcp", "python_dnspython_tcp", "local_authoritative", "direct_authoritative"),
            ("dns-python-rec-udp", "python_dnspython_udp", "local_recursive_forwarder", "recursive_resolver"),
            ("dns-python-rec-tcp", "python_dnspython_tcp", "local_recursive_forwarder", "recursive_resolver"),
        )
    if family in {"M-WSS-LONG", "M-TUNNEL"}:
        return (
            ("wss-python-direct", "python_websockets", "python_websockets_server", WSS_DIRECT),
            ("wss-python-nginx", "python_websockets", "nginx_to_wss", WSS_FRONT),
            ("wss-node-nginx", "node_websocket", "nginx_to_wss", WSS_FRONT),
            ("wss-chromium-nginx", "chromium_websocket", "nginx_to_wss", WSS_FRONT),
        )
    if family == "M-DOQ":
        return (
            ("doq-aioquic-newconn", "python_aioquic_doq", "aioquic_doq", "direct_doq"),
            ("doq-aioquic-reuse", "python_aioquic_doq_reuse", "aioquic_doq", "direct_doq"),
        )
    if family == "M-H3-QUIC":
        return (
            ("h3-aioquic-newconn", "python_aioquic_h3", "aioquic_h3", "cover-h3.test"),
            ("h3-aioquic-reuse", "python_aioquic_h3_reuse", "aioquic_h3", "cover-h3.test"),
            ("h3-aioquic-parallel", "python_aioquic_h3_parallel", "aioquic_h3", "cover-h3.test"),
        )
    if family == "M-CLOUD-API":
        return tuple(
            (f"cloud-api-{c}-{i}", c, "nginx_reverse_proxy", HTTPS_FRONTS[i % len(HTTPS_FRONTS)])
            for i, c in enumerate(HTTP_CLIENTS)
        )
    if family == "M-TIMING-XCARRIER":
        return (
            ("timing-https-curl", "curl_linux", "nginx_reverse_proxy", "edge-front.test"),
            ("timing-https-go", "go_nethttp", "nginx_reverse_proxy", "cdn-front.test"),
            ("timing-https-browser", "browser_chromium", "nginx_reverse_proxy", "workers-front.test"),
            ("timing-dns-udp", "python_dnspython_udp", "local_recursive_forwarder", "recursive_resolver"),
            ("timing-dns-tcp", "python_dnspython_tcp", "local_recursive_forwarder", "recursive_resolver"),
            ("timing-wss-python", "python_websockets", "python_websockets_server", WSS_DIRECT),
            ("timing-wss-node", "node_websocket", "nginx_to_wss", WSS_FRONT),
            ("timing-mqtt-paho", "paho_mqtt_websockets", "mosquitto_websockets", "mqtt-broker.test"),
        )
    if family == "M-PUBSUB-MQTT":
        return (
            ("mqtt-paho-qos0", "paho_mqtt_websockets", "mosquitto_websockets", "mqtt-broker.test"),
            ("mqtt-paho-qos1", "paho_mqtt_websockets_qos1", "mosquitto_websockets", "mqtt-broker.test"),
        )
    if family == "M-GRPC-BIDI":
        return (
            ("grpc-python-bidi", "grpcio", "grpcio_generic_h2", "cover-h2.test"),
            ("grpc-python-stream-unary", "grpcio_stream_unary", "grpcio_generic_h2", "cover-h2.test"),
        )
    if family == "M-HTTP-443":
        return tuple(
            (f"http443-{c}-nginx", c, "nginx_plain_http_443", "plain-front.test")
            for c in HTTP_CLIENTS[:6]
        )
    if family == "M-DOH":
        return tuple(
            (f"doh-{c}-{'direct' if i % 2 == 0 else 'nginx'}", c,
             "hypercorn" if i % 2 == 0 else "nginx_reverse_proxy",
             "doh-relay.test" if i % 2 == 0 else "resolver-front.test")
            for i, c in enumerate(HTTP_CLIENTS[:6])
        )
    if family == "M-HTTPS-FRONT":
        return tuple(
            (f"m-https-front-{c}-{i}", c, "nginx_reverse_proxy", HTTPS_FRONTS[i % len(HTTPS_FRONTS)])
            for i, c in enumerate(HTTP_CLIENTS)
        )
    if family in {"M-DEAD-DROP", "M-FALLBACK"}:
        return tuple(
            (f"{family.lower()}-{c}-{i%3}", c,
             "hypercorn+nginx+dns" if family == "M-FALLBACK" else "nginx+hypercorn",
             HTTPS_FRONTS[i % len(HTTPS_FRONTS)])
            for i, c in enumerate(HTTP_CLIENTS[:6])
        )
    # HTTPS beacon/front/low-entropy/fragment/RMM families.
    items = []
    for i, c in enumerate(HTTP_CLIENTS):
        server = "hypercorn" if i % 2 == 0 else "nginx_reverse_proxy"
        host = HTTPS_DIRECT[i % len(HTTPS_DIRECT)] if server == "hypercorn" else HTTPS_FRONTS[i % len(HTTPS_FRONTS)]
        items.append((f"{family.lower()}-{c}-{server}", c, server, host))
    return tuple(items)


def total_implementation_profiles() -> int:
    return sum(len(implementation_catalog(f)) for f in FAMILY_COUNTS)


def build_specs(mode: str = "full") -> list[CampaignSpec]:
    out: list[CampaignSpec] = []
    g = 0
    for family, count in FAMILY_COUNTS.items():
        impls = implementation_catalog(family)
        actual_count = count if mode == "full" else min(count, max(len(impls), 4))
        for j in range(actual_count):
            impl_id, client, server, topology = impls[j % len(impls)]
            front_host = topology if topology.endswith(".test") else ""
            interval_bucket = INTERVALS[(j // max(1, len(impls))) % len(INTERVALS)]
            # Do not manufacture thousands of "different" PCAPs by seed alone.
            # Keep the research cadence buckets, but vary the requested clock,
            # jitter and count deterministically inside each bucket.
            interval_delta = (((j * 37 + g * 13) % 97) - 48) / 1200.0
            interval = round(interval_bucket * (1.0 + interval_delta), 3)
            jitter_bucket = JITTERS[(j // 3) % len(JITTERS)]
            jitter = round(max(0.0, min(0.50, jitter_bucket + ((((j * 17 + g * 7) % 19) - 9) * 0.005))), 3)
            event_bucket = EVENT_COUNTS[(j * 5 + g) % len(EVENT_COUNTS)]
            events = max(3, min(120, event_bucket + ((j * 11 + g * 5) % 7) - 3))
            volume = VOLUME_MODES[(j // 2) % len(VOLUME_MODES)]
            asym = ASYMMETRY[(j // 5) % len(ASYMMETRY)]
            if family == "M-HTTPS-LOWENT":
                payload = "low_entropy"
            elif family == "M-HTTPS-FRAG":
                payload = "fragment_2_6"
            else:
                payload = PAYLOAD_MODES[(j // 7) % len(PAYLOAD_MODES)]
            out.append(CampaignSpec(
                index=g, family=family, family_index=j, implementation_id=impl_id,
                client_impl=client, server_impl=server, front_host=front_host,
                network_topology=(
                    topology if not topology.endswith(".test")
                    else "direct_wss" if topology == WSS_DIRECT
                    else "nginx_wss_front" if topology == WSS_FRONT
                    else "nginx_front" if topology in HTTPS_FRONTS or topology == "plain-front.test"
                    else "direct"
                ),
                interval_seconds=interval, interval_bucket_seconds=interval_bucket,
                jitter_fraction=jitter, event_count=events, event_count_bucket=event_bucket,
                volume_mode=volume, asymmetry=asym, payload_mode=payload,
                holdout_fold=_stable_mod(impl_id, 5),
            ))
            g += 1
    return out


def _set_server_state(source_ip: str, family: str, seed: int, campaign_id: str) -> None:
    path = Path("/tmp/coverlab_server_state.json")
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            raw = json.loads(path.read_text()) if path.exists() else {"clients": {}, "default": {}}
        except Exception:
            raw = {"clients": {}, "default": {}}
        state = {"scenario_id": family, "suspicious": True, "seed": seed, "campaign_id": campaign_id}
        raw.setdefault("clients", {})[source_ip] = state
        raw["default"] = state
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw))
        os.replace(tmp, path)
        fcntl.flock(lock, fcntl.LOCK_UN)


def _payload(r: random.Random, mode: str, i: int, size: int = 48) -> bytes:
    if mode == "low_entropy":
        vals = (b"id=do", b"status=ok", b"cmd=1", str(uuid.UUID(int=r.getrandbits(128))).encode())
        return vals[i % len(vals)]
    if mode == "fragment_2_6":
        alphabet = "abcdef0123456789"
        n = 2 + (i % 5)
        return "".join(r.choice(alphabet) for _ in range(n)).encode()
    raw = bytes(r.randrange(0, 256) for _ in range(size))
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _requested_sleep(spec: CampaignSpec, r: random.Random, i: int) -> None:
    if i + 1 >= spec.event_count:
        return
    factor = 1.0 + r.uniform(-spec.jitter_fraction, spec.jitter_fraction)
    requested = max(0.0, spec.interval_seconds * factor)
    scale = float(os.environ.get("COVERLAB_STAGE_M_TIME_SCALE", "0.001"))
    cap_raw = os.environ.get("COVERLAB_STAGE_M_MAX_SLEEP_SECONDS", "0.05")
    actual = requested * scale
    if cap_raw:
        actual = min(actual, float(cap_raw))
    if actual > 0:
        time.sleep(actual)


def _chromium_http(url: str, method: str, body: bytes | None) -> tuple[int, str]:
    chrome = os.environ.get("COVERLAB_CHROME") or next(
        (x for x in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
         if subprocess.run(["bash", "-lc", f"command -v {x}"], stdout=subprocess.DEVNULL).returncode == 0), ""
    )
    if not chrome:
        raise RuntimeError("Chromium unavailable for Stage M HTTPS implementation")
    u = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
    if u.hostname not in set(HTTPS_DIRECT) | set(HTTPS_FRONTS):
        raise RuntimeError("Chromium Stage M HTTP target is not allowlisted")
    # A local fixture page issues the requested POST/GET from Chromium itself,
    # giving a genuine browser TLS/HTTP stack while remaining inside .test.
    payload = base64.urlsafe_b64encode(body or b"").decode()
    fixture = (
        f"https://{u.hostname}:8443/stage-m/http-fixture"
        f"?target={__import__('urllib.parse', fromlist=['quote']).quote(u.path + ('?' + u.query if u.query else ''), safe='')}"
        f"&method={method}&body={__import__('urllib.parse', fromlist=['quote']).quote(payload, safe='')}"
    )
    cp = subprocess.run([
        chrome, "--headless", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
        "--disable-background-networking", "--disable-component-update", "--disable-sync",
        "--no-first-run", "--virtual-time-budget=4000", "--dump-dom", fixture,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25)
    if cp.returncode != 0:
        raise RuntimeError(f"Chromium Stage M HTTP returned {cp.returncode}")
    return 200, "browser_chromium"


def _http_exchange(client: str, method: str, url: str, headers: dict, body: bytes | None, use_h2: bool = False) -> tuple[int, str]:
    if client == "browser_chromium":
        return _chromium_http(url, method, body)
    if client == "chromium_websocket":
        client = "python_httpx"
    return rc.execute_http(client, method, url, headers, body, use_h2)


def _http_events(spec: CampaignSpec, r: random.Random, family: str) -> list[dict]:
    events: list[dict] = []
    host = spec.front_host or "cover-api.test"
    scheme = "https"
    port = 8443
    if family == "M-HTTP-443":
        host, scheme, port = "plain-front.test", "http", 443
    for i in range(spec.event_count):
        data = _payload(r, spec.payload_mode, i, 32 + (i % 4) * 24)
        method = "POST"
        path = "/stage-m/beacon"
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json", "X-Lab-Profile": "stage-m"}
        body: bytes | None = data
        if family == "M-HTTPS-FRAG":
            method, body = "GET", None
            path = f"/stage-m/item?id={data.decode(errors='ignore')}"
        elif family == "M-HTTPS-LOWENT":
            path = f"/stage-m/status?q={data.decode(errors='ignore')}"
            body = b'{"status":"ok","id":"do"}'
            headers["Content-Type"] = "application/json"
        elif family == "M-RMM-SHAPE":
            if i < max(2, spec.event_count // 2):
                method, body, path = "GET", None, f"/stage-m/poll?cursor={i}"
            else:
                n = 96 + (i % 5) * 192
                body = _payload(r, "high_entropy", i, n)
                path = "/stage-m/interactive"
        elif family == "M-HTTP-443":
            path = "/fakeurl.htm"
            body = b"status=" + data[:24]
        # Direction/size asymmetry without arbitrary forwarding.
        if spec.asymmetry in {"large_small", "upload_heavy"} and body is not None:
            body = body * 8
        if spec.asymmetry in {"small_large", "download_heavy"}:
            headers["X-Coverlab-Response-Size"] = "large"
        started = now_iso()
        status, effective = _http_exchange(spec.client_impl, method, f"{scheme}://{host}:{port}{path}", headers, body, use_h2=(host == "cover-h2.test"))
        events.append({
            "event_id": f"e{i:03d}", "event_type": "stage_m_http", "sent_at": started,
            "completed_at": now_iso(), "http_method": method, "http_path": path,
            "response_status": status, "encoded_length": len(body or b""),
            "effective_client_impl": effective,
        })
        _requested_sleep(spec, r, i)
    return events


def _dns_wire_query(qname: str, qtype: str) -> bytes:
    return dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.from_text(qtype)).to_wire()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _dns_exchange(server: str, wire: bytes, tcp: bool) -> int:
    attempts = int(os.environ.get("COVERLAB_STAGE_M_DNS_RETRIES", "5"))
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            if tcp:
                with socket.create_connection((server, 53), timeout=8) as s:
                    s.settimeout(8)
                    s.sendall(len(wire).to_bytes(2, "big") + wire)
                    head = _recv_exact(s, 2)
                    if len(head) != 2:
                        raise RuntimeError("short DNS/TCP length prefix")
                    need = int.from_bytes(head, "big")
                    data = _recv_exact(s, need)
                    if len(data) != need:
                        raise RuntimeError(f"short DNS/TCP response {len(data)}/{need}")
                    return len(data)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(8)
                s.sendto(wire, (server, 53))
                data, _ = s.recvfrom(65535)
                if len(data) < 12:
                    raise RuntimeError("short DNS/UDP response")
                return len(data)
        except (OSError, TimeoutError, RuntimeError) as exc:
            last = exc
            if attempt < attempts:
                time.sleep(min(2.0, 0.20 * (2 ** (attempt - 1))))
    raise RuntimeError(f"Stage M DNS exchange failed after {attempts} attempts server={server} tcp={tcp}: {last}")


def _dns_events(spec: CampaignSpec, r: random.Random, bulk: bool = False) -> list[dict]:
    tcp = spec.client_impl.endswith("_tcp")
    server = DNS_RECURSOR if spec.network_topology == "recursive_resolver" else DNS_AUTH
    events = []
    qtypes = ("A", "AAAA", "TXT")
    parent = "stage-m.test."
    for i in range(spec.event_count):
        raw = _payload(r, "high_entropy" if bulk else spec.payload_mode, i, 16 if not bulk else 32)
        label = base64.b32encode(raw).decode().rstrip("=").lower()[:63]
        if bulk and i % 7 == 0:
            label = "nx-" + label[:59]
        qname = f"{label}.{parent}"
        qtype = qtypes[i % len(qtypes)]
        wire = _dns_wire_query(qname, qtype)
        started = now_iso()
        reply_len = _dns_exchange(server, wire, tcp)
        events.append({
            "event_id": f"e{i:03d}", "event_type": "stage_m_dns", "sent_at": started,
            "completed_at": now_iso(), "dns_qname": qname, "dns_qtype": qtype,
            "encoded_length": len(wire), "reply_len": reply_len, "dns_tcp": tcp,
            "dns_server": server,
        })
        _requested_sleep(spec, r, i)
    return events


def _doh_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    events = []
    host = spec.front_host or "doh-relay.test"
    for i in range(spec.event_count):
        raw = _payload(r, spec.payload_mode, i, 16)
        label = base64.b32encode(raw).decode().rstrip("=").lower()[:50]
        qname = f"{label}.stage-m.test."
        qtype = ("A", "AAAA", "TXT")[i % 3]
        wire = _dns_wire_query(qname, qtype)
        started = now_iso()
        status, effective = _http_exchange(
            spec.client_impl, "POST", f"https://{host}:8443/dns-query",
            {"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
            wire, use_h2=(spec.client_impl == "python_httpx_h2"),
        )
        events.append({
            "event_id": f"e{i:03d}", "event_type": "stage_m_doh", "sent_at": started,
            "completed_at": now_iso(), "dns_qname": qname, "dns_qtype": qtype,
            "response_status": status, "encoded_length": len(wire), "effective_client_impl": effective,
        })
        _requested_sleep(spec, r, i)
    return events


async def _doq_batch(spec: CampaignSpec, r: random.Random) -> list[dict]:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=DOQ_ALPN)
    cfg.verify_mode = ssl.CERT_NONE
    host = "doq-resolver.test"
    reuse = spec.client_impl.endswith("_reuse")
    out: list[dict] = []

    async def emit(proto: DoQClientProtocol, i: int) -> dict:
        raw = _payload(r, spec.payload_mode, i, 18 + (i % 4) * 8)
        label = base64.b32encode(raw).decode().rstrip("=").lower()[:50]
        qname = f"{label}.stage-m.test."
        qtype = ("A", "AAAA", "TXT")[i % 3]
        wire = _dns_wire_query(qname, qtype)
        started = now_iso()
        reply = await proto.query(wire, timeout=12)
        return {
            "event_id": f"e{i:03d}", "event_type": "stage_m_doq",
            "sent_at": started, "completed_at": now_iso(),
            "dns_qname": qname, "dns_qtype": qtype,
            "encoded_length": len(wire), "reply_len": len(reply),
            "quic_connection_reused": reuse,
            "alpn": "doq",
        }

    if reuse:
        async with quic_connect(
            host, 8853, configuration=cfg,
            create_protocol=DoQClientProtocol, server_name=host,
        ) as proto:
            for i in range(spec.event_count):
                out.append(await emit(proto, i))
                _requested_sleep(spec, r, i)
    else:
        for i in range(spec.event_count):
            async with quic_connect(
                host, 8853, configuration=cfg,
                create_protocol=DoQClientProtocol, server_name=host,
            ) as proto:
                out.append(await emit(proto, i))
            _requested_sleep(spec, r, i)
    return out


def _doq_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    attempts = int(os.environ.get("COVERLAB_STAGE_M_QUIC_RETRIES", "4"))
    last = None
    for attempt in range(1, attempts + 1):
        try:
            rows = asyncio.run(_doq_batch(spec, r))
            for row in rows:
                row["transport_attempt"] = attempt
            return rows
        except (TimeoutError, OSError, ConnectionError) as exc:
            last = exc
            time.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
    raise RuntimeError(f"Stage M DoQ failed after {attempts} attempts: {last}")


async def _h3_batch(spec: CampaignSpec, r: random.Random) -> list[dict]:
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65536,
    )
    cfg.verify_mode = ssl.CERT_NONE
    host = "cover-h3.test"
    authority = f"{host}:8444"
    reuse = spec.client_impl.endswith("_reuse")
    parallel = spec.client_impl.endswith("_parallel")
    out: list[dict] = []

    async def emit(proto: LabH3Client, i: int) -> dict:
        body = _payload(r, spec.payload_mode, i, 24 + (i % 6) * 64)
        path = f"/stage-m/h3/{spec.index}/{i}"
        started = now_iso()
        reply = await proto.request(authority, path, "POST", body)
        return {
            "event_id": f"e{i:03d}",
            "event_type": "stage_m_h3",
            "sent_at": started,
            "completed_at": now_iso(),
            "http_method": "POST",
            "http_path": path,
            "response_status": int(reply.get("status") or 0),
            "encoded_length": len(body),
            "reply_len": int(reply.get("response_bytes") or 0),
            "h3_stream_id": int(reply.get("stream_id") or 0),
            "quic_connection_reused": bool(reuse or parallel),
            "h3_parallel_streams": bool(parallel),
            "alpn": "h3",
        }

    if reuse or parallel:
        async with quic_connect(
            host, 8444, configuration=cfg,
            create_protocol=LabH3Client, server_name=host,
        ) as proto:
            if parallel:
                width = min(8, max(1, spec.event_count))
                for start in range(0, spec.event_count, width):
                    batch = [emit(proto, i) for i in range(start, min(start + width, spec.event_count))]
                    out.extend(await asyncio.gather(*batch))
                    if start + width < spec.event_count:
                        _requested_sleep(spec, r, min(start + width - 1, spec.event_count - 1))
            else:
                for i in range(spec.event_count):
                    out.append(await emit(proto, i))
                    _requested_sleep(spec, r, i)
    else:
        for i in range(spec.event_count):
            async with quic_connect(
                host, 8444, configuration=cfg,
                create_protocol=LabH3Client, server_name=host,
            ) as proto:
                out.append(await emit(proto, i))
            _requested_sleep(spec, r, i)
    return out


def _h3_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    attempts = int(os.environ.get("COVERLAB_STAGE_M_QUIC_RETRIES", "4"))
    last = None
    for attempt in range(1, attempts + 1):
        try:
            rows = asyncio.run(_h3_batch(spec, r))
            for row in rows:
                row["transport_attempt"] = attempt
            return rows
        except (TimeoutError, OSError, ConnectionError, RuntimeError) as exc:
            last = exc
            time.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
    raise RuntimeError(f"Stage M H3 failed after {attempts} attempts: {last}")


def _cloud_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    hosts = ("graph-front.test", "workers-front.test", "cdn-front.test", "telegram-front.test")
    templates = (
        ("/v1.0/me/drive/items/{id}/content", "GET"),
        ("/v4/spreadsheets/{id}/values/A1", "GET"),
        ("/storage/v1/b/lab/o/{id}", "PUT"),
        ("/yandex/disk/resources?path=/lab/{id}", "GET"),
        ("/api/blob/{id}", "POST"),
    )
    out = []
    for i in range(spec.event_count):
        ident = hashlib.sha256(f"{spec.index}:{i}".encode()).hexdigest()[:16]
        tpl, method = templates[i % len(templates)]
        path = tpl.format(id=ident)
        host = hosts[(spec.family_index + i) % len(hosts)]
        body = None if method == "GET" else _payload(r, spec.payload_mode, i, 32 + (i % 6) * 64)
        started = now_iso()
        status, effective = _http_exchange(
            spec.client_impl, method, f"https://{host}:8443{path}",
            {"Accept": "application/json", "Content-Type": "application/octet-stream", "X-Client-Request-Id": ident},
            body,
        )
        out.append({
            "event_id": f"e{i:03d}", "event_type": "stage_m_cloud_api",
            "sent_at": started, "completed_at": now_iso(),
            "http_method": method, "http_path": path, "response_status": status,
            "encoded_length": len(body or b""), "effective_client_impl": effective,
            "service_mimic": ("graph", "sheets", "blob", "disk", "object_api")[i % 5],
        })
        _requested_sleep(spec, r, i)
    return out


def _mqtt_events(spec: CampaignSpec, r: random.Random, *, timing: bool = False) -> list[dict]:
    qos = 1 if "qos1" in spec.implementation_id else 0
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"stage-m-{spec.index:06d}",
        protocol=mqtt.MQTTv5,
        transport="websockets",
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    client.tls_set_context(ctx)
    client.ws_set_options(path="/mqtt")
    last = None
    for attempt in range(1, 5):
        try:
            client.connect("mqtt-broker.test", 9443, keepalive=30)
            last = None
            break
        except OSError as exc:
            last = exc
            time.sleep(min(2.0, 0.25 * (2 ** (attempt - 1))))
    if last is not None:
        raise RuntimeError(f"MQTT connect failed: {last}")
    client.loop_start()
    out = []
    try:
        for i in range(spec.event_count):
            topic = f"control/stage-m/{spec.index % 32}/{i % 5}"
            payload = _payload(r, spec.payload_mode, i, 24 + (i % 5) * 48)
            started = now_iso()
            info = client.publish(topic, payload=payload, qos=qos, retain=(i % 17 == 0))
            info.wait_for_publish(timeout=10)
            out.append({
                "event_id": f"e{i:03d}", "event_type": "stage_m_mqtt",
                "sent_at": started, "completed_at": now_iso(),
                "mqtt_topic": topic, "mqtt_qos": qos, "encoded_length": len(payload),
                "response_status": 200,
            })
            if timing:
                _requested_sleep(spec, r, i)
    finally:
        client.disconnect()
        client.loop_stop()
    return out


def _grpc_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    channel = grpc.insecure_channel("cover-h2.test:50051")
    out = []
    payloads = [_payload(r, spec.payload_mode, i, 32 + (i % 4) * 64) for i in range(spec.event_count)]
    try:
        if spec.client_impl == "grpcio_stream_unary":
            call = channel.stream_unary(
                "/coverlab.Control/ClientStream",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            started = now_iso()
            reply = call(iter(payloads), timeout=20)
            out.append({
                "event_id": "e000", "event_type": "stage_m_grpc_stream_unary",
                "sent_at": started, "completed_at": now_iso(),
                "encoded_length": sum(map(len, payloads)), "reply_len": len(reply),
                "response_status": 200,
            })
        else:
            call = channel.stream_stream(
                "/coverlab.Control/Bidi",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            started = now_iso()
            replies = list(call(iter(payloads), timeout=30))
            for i, (req, reply) in enumerate(zip(payloads, replies)):
                out.append({
                    "event_id": f"e{i:03d}", "event_type": "stage_m_grpc_bidi",
                    "sent_at": started, "completed_at": now_iso(),
                    "encoded_length": len(req), "reply_len": len(reply),
                    "response_status": 200,
                })
    finally:
        channel.close()
    return out


def _timing_xcarrier_events(spec: CampaignSpec, r: random.Random, seed: int) -> tuple[list[dict], str]:
    impl = spec.implementation_id
    if impl.startswith("timing-https"):
        return _http_events(spec, r, "M-TIMING-XCARRIER"), "https"
    if impl.startswith("timing-dns"):
        return _dns_events(spec, r, bulk=False), "dns"
    if impl.startswith("timing-wss"):
        return _wss_events(spec, r, seed, tunnel=False), "wss"
    if impl.startswith("timing-mqtt"):
        return _mqtt_events(spec, r, timing=True), "mqtt+wss"
    raise RuntimeError(f"unknown cross-carrier timing implementation: {impl}")


def _python_wss(spec: CampaignSpec, r: random.Random, tunnel: bool) -> list[dict]:
    host = spec.front_host or WSS_DIRECT
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    events = []
    ws = None
    connect_attempt = 0
    max_attempts = int(os.environ.get("COVERLAB_STAGE_M_WSS_RETRIES", "5"))
    try:
        for i in range(spec.event_count):
            data = _payload(r, spec.payload_mode, i, 24 + (i % 5) * 32)
            if tunnel:
                conn = f"m{i % 4}"
                msg = {"type": "socks_data", "conn_id": conn, "data": base64.b64encode(data).decode()}
            else:
                msg = {"action": "send" if i % 2 else "recv", "container": data.decode(errors="ignore"), "target": "LAB", "message": "STATUS"}

            attempt = 0
            while True:
                attempt += 1
                connect_attempt += 1
                started = now_iso()
                try:
                    if ws is None:
                        ws = ws_connect(
                            f"wss://{host}:8443/ws",
                            ssl=ctx,
                            open_timeout=20,
                            close_timeout=2,
                            proxy=None,
                            compression=None,
                        )
                    ws.send(json.dumps(msg, separators=(",", ":")))
                    reply = ws.recv(timeout=20)
                    events.append({
                        "event_id": f"e{i:03d}", "event_type": "stage_m_wss", "sent_at": started,
                        "completed_at": now_iso(), "encoded_length": len(json.dumps(msg)),
                        "reply_len": len(reply), "wss_client_impl": "python_websockets",
                        "transport_attempt": attempt, "session_connect_ordinal": connect_attempt,
                    })
                    break
                except (TimeoutError, OSError, ssl.SSLError, ConnectionClosed, WebSocketException) as exc:
                    if ws is not None:
                        try:
                            ws.close()
                        except Exception:
                            pass
                        ws = None
                    if attempt >= max_attempts:
                        raise RuntimeError(
                            f"python Stage M WSS failed after {attempt} attempts host={host} event={i}: {exc}"
                        ) from exc
                    time.sleep(min(2.0, 0.20 * (2 ** (attempt - 1))))
            _requested_sleep(spec, r, i)
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
    return events


def _node_wss(spec: CampaignSpec, seed: int, tunnel: bool) -> list[dict]:
    root = Path(__file__).resolve().parents[2]
    cmd = [
        "node", str(root / "clients" / "stage_m_ws_client.mjs"),
        "--url", f"wss://{spec.front_host or WSS_FRONT}:8443/ws",
        "--events", str(spec.event_count), "--seed", str(seed),
        "--mode", "tunnel" if tunnel else "wss",
    ]
    last = None
    for attempt in range(1, int(os.environ.get("COVERLAB_STAGE_M_WSS_RETRIES", "5")) + 1):
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        if cp.returncode == 0:
            rows = [json.loads(x) for x in cp.stdout.splitlines() if x.strip().startswith("{")]
            for row in rows:
                row["transport_attempt"] = attempt
            return rows
        last = cp.stderr[-800:]
        time.sleep(min(2.0, 0.20 * (2 ** (attempt - 1))))
    raise RuntimeError("node stage-m WSS failed after bounded retries: " + str(last))


def _chromium_wss(spec: CampaignSpec, seed: int, tunnel: bool) -> list[dict]:
    chrome = os.environ.get("COVERLAB_CHROME") or next(
        (x for x in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
         if subprocess.run(["bash", "-lc", f"command -v {x}"], stdout=subprocess.DEVNULL).returncode == 0), ""
    )
    if not chrome:
        raise RuntimeError("Chromium unavailable for Stage M browser implementation")
    host = spec.front_host or WSS_FRONT
    url = (
        f"https://edge-front.test:8443/stage-m/ws-fixture"
        f"?host={host}&events={min(spec.event_count,20)}&seed={seed}&mode={'tunnel' if tunnel else 'wss'}"
    )
    last_rc = None
    for attempt in range(1, int(os.environ.get("COVERLAB_STAGE_M_WSS_RETRIES", "5")) + 1):
        cp = subprocess.run([
            chrome, "--headless", "--no-sandbox", "--disable-gpu", "--ignore-certificate-errors",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--no-first-run", "--virtual-time-budget=8000", "--dump-dom", url,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        if cp.returncode == 0:
            # Browser network activity is the evidence; event rows retain requested shape.
            return [{
                "event_id": f"e{i:03d}", "event_type": "stage_m_wss_browser",
                "sent_at": now_iso(), "completed_at": now_iso(), "encoded_length": 0,
                "reply_len": 0, "wss_client_impl": "chromium_websocket",
                "transport_attempt": attempt,
            } for i in range(min(spec.event_count, 20))]
        last_rc = cp.returncode
        time.sleep(min(2.0, 0.20 * (2 ** (attempt - 1))))
    raise RuntimeError(f"Chromium Stage M WSS failed after bounded retries rc={last_rc}")


def _wss_events(spec: CampaignSpec, r: random.Random, seed: int, tunnel: bool = False) -> list[dict]:
    if spec.client_impl == "node_websocket":
        return _node_wss(spec, seed, tunnel)
    if spec.client_impl == "chromium_websocket":
        return _chromium_wss(spec, seed, tunnel)
    return _python_wss(spec, r, tunnel)


def _dead_drop_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    first = spec.front_host or "graph-front.test"
    status1, c1 = _http_exchange(spec.client_impl, "GET", f"https://{first}:8443/stage-m/dead-drop", {"User-Agent": "Mozilla/5.0"}, None)
    gap = min(0.05, float(os.environ.get("COVERLAB_STAGE_M_DEAD_DROP_GAP_SECONDS", "0.02")))
    time.sleep(gap)
    status2, c2 = _http_exchange(spec.client_impl, "POST", "https://cover-api.test:8443/stage-m/beacon", {"Content-Type": "application/json"}, _payload(r, spec.payload_mode, 0, 48))
    return [
        {"event_id": "e000", "event_type": "dead_drop_pointer", "sent_at": now_iso(), "completed_at": now_iso(), "response_status": status1, "effective_client_impl": c1, "transport_phase": "pointer"},
        {"event_id": "e001", "event_type": "dead_drop_followup", "sent_at": now_iso(), "completed_at": now_iso(), "response_status": status2, "effective_client_impl": c2, "transport_phase": "https_c2"},
    ]


def _fallback_events(spec: CampaignSpec, r: random.Random) -> list[dict]:
    n1 = max(1, spec.event_count // 2)
    n2 = max(1, spec.event_count - n1)
    events = []
    for i in range(n1):
        status, eff = _http_exchange(spec.client_impl, "POST", "https://cover-api.test:8443/stage-m/primary", {"Content-Type": "application/octet-stream"}, _payload(r, spec.payload_mode, i, 32))
        events.append({"event_id": f"e{i:03d}", "event_type": "fallback_https", "sent_at": now_iso(), "completed_at": now_iso(), "response_status": status, "effective_client_impl": eff, "transport_phase": "https"})
    dns_spec = CampaignSpec(**{**spec.__dict__, "event_count": n2, "client_impl": "python_dnspython_udp", "network_topology": "recursive_resolver"})
    for j, evt in enumerate(_dns_events(dns_spec, r, bulk=False), start=n1):
        evt["event_id"] = f"e{j:03d}"
        evt["transport_phase"] = "dns"
        events.append(evt)
    return events


def run_one(spec: CampaignSpec, seed: int, campaign_id: str, persona: str, source_ip: str, capture_file: str) -> tuple[dict, list[dict]]:
    r = random.Random(seed)
    _set_server_state(source_ip, spec.family, seed, campaign_id)
    started = now_iso()
    if spec.family == "M-DNS-BEACON":
        events = _dns_events(spec, r, bulk=False)
        protocol = "dns"
    elif spec.family == "M-DNS-BULK":
        events = _dns_events(spec, r, bulk=True)
        protocol = "dns"
    elif spec.family == "M-DOH":
        events = _doh_events(spec, r)
        protocol = "https+doh"
    elif spec.family == "M-DOQ":
        events = _doq_events(spec, r)
        protocol = "doq+quic"
    elif spec.family == "M-H3-QUIC":
        events = _h3_events(spec, r)
        protocol = "h3+quic"
    elif spec.family == "M-CLOUD-API":
        events = _cloud_events(spec, r)
        protocol = "https"
    elif spec.family == "M-TIMING-XCARRIER":
        events, protocol = _timing_xcarrier_events(spec, r, seed)
    elif spec.family == "M-PUBSUB-MQTT":
        events = _mqtt_events(spec, r, timing=False)
        protocol = "mqtt+wss"
    elif spec.family == "M-GRPC-BIDI":
        events = _grpc_events(spec, r)
        protocol = "grpc+h2"
    elif spec.family == "M-WSS-LONG":
        events = _wss_events(spec, r, seed, tunnel=False)
        protocol = "wss"
    elif spec.family == "M-TUNNEL":
        events = _wss_events(spec, r, seed, tunnel=True)
        protocol = "wss"
    elif spec.family == "M-DEAD-DROP":
        events = _dead_drop_events(spec, r)
        protocol = "https+https"
    elif spec.family == "M-FALLBACK":
        events = _fallback_events(spec, r)
        protocol = "https+dns"
    else:
        events = _http_events(spec, r, spec.family)
        protocol = "http" if spec.family == "M-HTTP-443" else "https"

    scale = float(os.environ.get("COVERLAB_STAGE_M_TIME_SCALE", "0.001"))
    environment_tier = os.environ.get("COVERLAB_ENVIRONMENT_TIER", "ci_netns")
    wire_vm = environment_tier in {"vm_wire", "self_hosted_vm", "cross_host_wire"}
    mechanism = (
        "timing" if spec.family in {"M-HTTPS-BEACON", "M-WSS-LONG", "M-RMM-SHAPE", "M-TIMING-XCARRIER"}
        else "multi_carrier" if spec.family in {"M-FALLBACK", "M-DEAD-DROP"}
        else "storage"
    )
    embedding_locus = (
        "session_sequence" if mechanism in {"timing", "multi_carrier"}
        else "dns_message" if spec.family.startswith("M-DNS") or spec.family in {"M-DOH", "M-DOQ"}
        else "application_message"
    )
    timing_real = bool(math.isclose(scale, 1.0) and not os.environ.get("COVERLAB_STAGE_M_MAX_SLEEP_SECONDS"))
    manifest = {
        "campaign_id": campaign_id,
        "run_id": "stage-m",
        "scenario_id": spec.family,
        "label_binary": 1,
        "label_family": "cover_channel",
        "label_intent": "c2_or_tunnel_shape",
        "attack_mapping": ATTACK_MAPPING[spec.family],
        "protocol": protocol,
        "carrier": spec.family.lower().replace("m-", "").replace("-", "_"),
        "visibility_mode": "opaque_and_ground_truth" if any(x in protocol for x in ("https", "wss", "doq", "quic", "h3")) else "content",
        "inspection_policy": "bypass" if any(x in protocol for x in ("https", "wss", "doq", "quic", "h3")) else "not_applicable",
        "inspection_outcome": "encrypted" if any(x in protocol for x in ("https", "wss", "doq", "quic", "h3")) else "plaintext",
        "sni_visibility": "clear" if any(x in protocol for x in ("https", "wss", "doq", "quic", "h3")) else "not_applicable",
        "feature_availability_bitmap": "runtime",
        "experiment_stage": "M_positive_diversity",
        "dataset_role": "positive_corpus",
        "training_eligible": bool(wire_vm and (mechanism != "timing" or timing_real)),
        "channel_mechanism": mechanism,
        "embedding_locus": embedding_locus,
        "modulation_scheme": "periodic_jittered" if mechanism == "timing" else spec.payload_mode,
        "cover_behavior": spec.volume_mode,
        "temporal_profile": f"{spec.interval_seconds}s_jitter_{int(spec.jitter_fraction*100)}pct",
        "payload_entropy_class": spec.payload_mode,
        "payload_size_profile": spec.asymmetry,
        "transport_chain": protocol,
        "parent_campaign_id": None,
        "mutation_epoch": 0,
        "mutation_policy": "fixed_catalog",
        "network_profile_id": os.environ.get("COVERLAB_NETEM_PROFILE", "clean"),
        "clock_profile_id": os.environ.get("COVERLAB_CLOCK_PROFILE", "host_default"),
        "tls_profile_id": spec.client_impl if any(x in protocol for x in ("https", "wss")) else "none",
        "quic_profile_id": spec.client_impl if any(x in protocol for x in ("doq", "quic")) else "none",
        "dns_transport": "doq" if "doq" in protocol else ("tcp" if spec.client_impl.endswith("_tcp") else ("udp" if "dns" in protocol else "none")),
        "service_mimic_category": spec.front_host or "direct_lab_service",
        "seed_origin": "deterministic_coverlab",
        "seed_license": "synthetic",
        "concept_epoch": os.environ.get("COVERLAB_CONCEPT_EPOCH", "2026-09"),
        "external_implementation": False,
        "ground_truth_source": "lab_orchestrator",
        "capture_environment": environment_tier,
        "negative_class_present": False,
        "positive_only": True,
        "implementation_id": spec.implementation_id,
        "client_impl": spec.client_impl,
        "server_impl": spec.server_impl,
        "network_topology": spec.network_topology,
        "front_host_category": spec.front_host,
        "netem_profile": os.environ.get("COVERLAB_NETEM_PROFILE", "clean"),
        "requested_interval_seconds": spec.interval_seconds,
        "interval_bucket_seconds": spec.interval_bucket_seconds,
        "jitter_fraction": spec.jitter_fraction,
        "event_count_target": spec.event_count,
        "event_count_bucket": spec.event_count_bucket,
        "volume_mode": spec.volume_mode,
        "direction_asymmetry": spec.asymmetry,
        "payload_mode": spec.payload_mode,
        "timing_scale": scale,
        "timing_fidelity": "wire_real" if math.isclose(scale, 1.0) and not os.environ.get("COVERLAB_STAGE_M_MAX_SLEEP_SECONDS") else "accelerated_shape_only",
        "timing_training_eligible": timing_real,
        "holdout_fold": spec.holdout_fold,
        "leave_one_implementation_group": spec.implementation_id,
        "leave_one_client_group": spec.client_impl,
        "leave_one_server_group": spec.server_impl,
        "leave_one_network_group": os.environ.get("COVERLAB_NETEM_PROFILE", "clean"),
        "persona": persona,
        "source_ip": source_ip,
        "destination_host": spec.front_host,
        "capture_file": capture_file,
        "seed": seed,
        "expected_events": len(events),
        "started_at": started,
        "ended_at": now_iso(),
        "status": "success",
        "generator_name": "coverlab_stage_m_positive",
        "generator_version": "1.0.0",
        "generator_commit": os.environ.get("GITHUB_SHA", "local"),
        "external_dependency": False,
        "post_exploitation": False,
        "arbitrary_forwarding": False,
        "infra_category": "synthetic_local_fixture",
    }
    for e in events:
        e.update({
            "campaign_id": campaign_id, "run_id": "stage-m", "scenario_id": spec.family,
            "label_binary": 1, "implementation_id": spec.implementation_id,
        })
    return manifest, events


def generate(args: argparse.Namespace) -> dict:
    specs = build_specs(args.mode)
    family_filter = {x.strip() for x in os.environ.get("COVERLAB_STAGE_M_FAMILY_FILTER", "").split(",") if x.strip()}
    if family_filter:
        specs = [s for s in specs if s.family in family_filter]
    force_interval = os.environ.get("COVERLAB_STAGE_M_FORCE_INTERVAL_SECONDS")
    event_cap = int(os.environ.get("COVERLAB_STAGE_M_EVENT_COUNT_CAP", "0") or 0)
    if force_interval:
        specs = [replace(s, interval_seconds=float(force_interval), interval_bucket_seconds=int(float(force_interval))) for s in specs]
    if event_cap > 0:
        specs = [replace(s, event_count=min(s.event_count, event_cap), event_count_bucket=min(s.event_count_bucket, event_cap)) for s in specs]
    spec_offset = int(os.environ.get("COVERLAB_STAGE_M_SPEC_OFFSET", "0") or 0)
    if spec_offset > 0:
        specs = specs[spec_offset:]
    campaign_limit = int(os.environ.get("COVERLAB_STAGE_M_CAMPAIGN_LIMIT", "0") or 0)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "campaigns.jsonl"
    events_path = out / "events.jsonl"
    manifest_path.touch()
    events_path.touch()
    selected = 0
    persona, source_ip = PERSONAS[args.persona_index]
    with manifest_path.open("a", encoding="utf-8") as mf, events_path.open("a", encoding="utf-8") as ef:
        for spec in specs:
            if spec.index % args.shards != args.shard:
                continue
            if spec.index % len(PERSONAS) != args.persona_index:
                continue
            seed = args.seed + spec.index * 1009
            cid = f"m-{spec.index:05d}-{spec.family_index:04d}"
            record, events = run_one(spec, seed, cid, persona, source_ip, args.capture_file)
            mf.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            for evt in events:
                ef.write(json.dumps(evt, separators=(",", ":"), default=str) + "\n")
            selected += 1
            if campaign_limit and selected >= campaign_limit:
                break
    result = {
        "mode": args.mode,
        "shard": args.shard,
        "shards": args.shards,
        "persona_index": args.persona_index,
        "campaigns": selected,
        "catalog_campaigns": len(specs),
        "full_budget": sum(FAMILY_COUNTS.values()),
        "implementation_profiles": total_implementation_profiles(),
        "positive_only": True,
    }
    print(json.dumps(result, sort_keys=True))
    return result


def validate_manifest(path: Path, *, require_full: bool = False) -> dict:
    rows = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    errors: list[str] = []
    families: dict[str, int] = {}
    impls: set[str] = set()
    for r in rows:
        cid = str(r.get("campaign_id", ""))
        if int(r.get("label_binary", 0)) != 1:
            errors.append(f"{cid}: non-positive label in Stage M")
        if r.get("positive_only") is not True or r.get("negative_class_present") is not False:
            errors.append(f"{cid}: positive-only contract missing")
        if r.get("external_dependency") is not False or r.get("arbitrary_forwarding") is not False:
            errors.append(f"{cid}: unsafe/external provenance")
        fam = str(r.get("scenario_id", ""))
        families[fam] = families.get(fam, 0) + 1
        impls.add(str(r.get("implementation_id", "")))
    if require_full:
        missing = sorted(set(FAMILY_COUNTS) - set(families))
        if missing:
            errors.append("missing families: " + ",".join(missing))
        if len(rows) != sum(FAMILY_COUNTS.values()):
            errors.append(f"expected {sum(FAMILY_COUNTS.values())} campaigns, got {len(rows)}")
    return {
        "passed": not errors,
        "positive_only": True,
        "campaigns": len(rows),
        "families": families,
        "implementation_profiles_observed": len(impls),
        "implementation_profiles_catalog": total_implementation_profiles(),
        "errors": errors[:100],
    }


def main() -> None:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", required=True)
    g.add_argument("--capture-file", required=True)
    g.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    g.add_argument("--seed", type=int, default=26092301)
    g.add_argument("--shard", type=int, default=0)
    g.add_argument("--shards", type=int, default=1)
    g.add_argument("--persona-index", type=int, choices=[0, 1, 2, 3], default=0)
    v = sub.add_parser("validate")
    v.add_argument("--manifest", required=True)
    v.add_argument("--require-full", action="store_true")
    a = p.parse_args()
    if a.cmd == "generate":
        generate(a)
    else:
        report = validate_manifest(Path(a.manifest), require_full=a.require_full)
        print(json.dumps(report, indent=2, sort_keys=True))
        if not report["passed"]:
            raise SystemExit("Stage M positive-only contract failed")


if __name__ == "__main__":
    main()
