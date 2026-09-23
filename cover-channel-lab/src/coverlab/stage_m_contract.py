from __future__ import annotations

"""Stage M positive-only corpus contract.

The contract intentionally models *network shapes*, not malware products.  Every
endpoint is a local ``.test`` fixture and all generated campaigns are positive
examples.  Real office/legitimate traffic is introduced only in a later stage.
"""

from dataclasses import asdict, dataclass
import hashlib
from typing import Iterable

NETWORK_PROFILES = ("clean", "wan_20ms", "wan_80ms", "lossy_wifi", "constrained")
EVENT_COUNTS = (3, 5, 10, 20, 50, 100)
NOMINAL_INTERVAL_SECONDS = (30, 60, 300, 900, 3600)
JITTER_FRACTIONS = (0.0, 0.10, 0.30)
DIRECTION_PROFILES = ("balanced", "upload_heavy", "download_heavy", "alternating")
FRONT_HOSTS = (
    "front-cdn.test",
    "front-workers.test",
    "front-graph.test",
    "front-telegram.test",
    "front-resolver.test",
)
LOCAL_HOSTS = frozenset({
    *FRONT_HOSTS,
    "cover-api.test",
    "cover-ws.test",
    "plain-http.test",
    "doh-relay.test",
    "stage-m-go.test",
    "stage-m-node.test",
    "stage-m-tcp.test",
    "stage-m-dns.test",
    "stage-m-resolver.test",
})


@dataclass(frozen=True)
class StageMFamily:
    family_id: str
    transport: str
    core_count: int
    diversity_count: int
    holdout_count: int
    attack_mapping: tuple[str, ...]
    description: str

    @property
    def total_count(self) -> int:
        return self.core_count + self.diversity_count + self.holdout_count


FAMILIES: tuple[StageMFamily, ...] = (
    StageMFamily("M-HTTPS-BEACON", "https", 400, 180, 100, ("T1071.001", "T1573"), "HTTPS beacon with interval/jitter and sparse asymmetric bursts"),
    StageMFamily("M-HTTPS-FRONT", "https", 400, 150, 80, ("T1071.001", "T1102", "T1090"), "HTTPS beacon to a local shared-front alias"),
    StageMFamily("M-HTTPS-LOWENT", "https", 200, 40, 0, ("T1071.001",), "Low-entropy short code/GUID payloads shaped like normal API traffic"),
    StageMFamily("M-HTTPS-FRAG", "https", 200, 40, 0, ("T1071.001", "T1001.001"), "2-6 character fragments over a series of small requests"),
    StageMFamily("M-HTTP-443", "http", 200, 40, 20, ("T1071.001",), "Plain HTTP on 443/80 with periodic small polls"),
    StageMFamily("M-DNS-BEACON", "dns", 300, 150, 80, ("T1071.004",), "Low-QPS DNS beacon over UDP/TCP and direct/resolver paths"),
    StageMFamily("M-DNS-BULK", "dns", 200, 100, 60, ("T1071.004", "T1041"), "Burst of unique subdomains across A/AAAA/TXT"),
    StageMFamily("M-DOH", "https", 150, 60, 40, ("T1071.004", "T1573"), "DNS wire messages over local DoH GET/POST"),
    StageMFamily("M-DEAD-DROP", "https", 200, 60, 20, ("T1102.001", "T1071.001"), "Short local shared-service lookup followed by separate HTTPS beacon"),
    StageMFamily("M-WSS-LONG", "wss", 250, 150, 80, ("T1071.001", "T1573"), "Long-lived bidirectional WebSocket with sparse and burst phases"),
    StageMFamily("M-TUNNEL", "tcp", 200, 150, 80, ("T1572", "T1090"), "Bounded local duplex TCP fixture with no forwarding"),
    StageMFamily("M-FALLBACK", "multi", 150, 80, 40, ("T1071.001", "T1071.004"), "Same campaign switches HTTPS<->DNS after a bounded failed-primary phase"),
    StageMFamily("M-RMM-SHAPE", "https", 100, 0, 0, ("T1219",), "Remote-management-like poll then interactive burst shape only"),
)

FAMILY_BY_ID = {f.family_id: f for f in FAMILIES}
EXPECTED_TOTAL_CAMPAIGNS = sum(f.total_count for f in FAMILIES)
assert EXPECTED_TOTAL_CAMPAIGNS == 4750

HTTP_CLIENTS = (
    "python_httpx",
    "python_httpx_h2",
    "curl_linux",
    "go_nethttp",
    "node_fetch",
    "java_httpclient",
    "rust_reqwest",
    "python_stdlib",
    "browser_chromium",
)
HTTP_SERVERS = ("hypercorn", "go_nethttp_server", "node_http_server")
DNS_CLIENTS = ("dnspython", "dig", "raw_socket")
DNS_PATHS = ("direct_authoritative", "recursive_resolver")
WSS_CLIENTS = ("python_websockets", "java_websocket", "chromium_websocket")
WSS_SERVERS = ("python_websockets_server", "hypercorn_asgi")
TUNNEL_CLIENTS = ("python_socket", "go_socket", "java_socket")
TUNNEL_FRAMING = ("fixed", "length_prefixed", "line")


def _stable_int(*parts: object) -> int:
    raw = "\x1f".join(map(str, parts)).encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def _http_implementations() -> tuple[dict, ...]:
    # Curated rather than full Cartesian product: each client and each server
    # appears repeatedly, while keeping the corpus size under control.
    pairs = (
        ("python_httpx", "hypercorn", "keepalive"),
        ("python_httpx_h2", "hypercorn", "keepalive"),
        ("curl_linux", "go_nethttp_server", "reconnect"),
        ("go_nethttp", "node_http_server", "reconnect"),
        ("node_fetch", "hypercorn", "reconnect"),
        ("java_httpclient", "go_nethttp_server", "reconnect"),
        ("rust_reqwest", "node_http_server", "reconnect"),
        ("python_stdlib", "go_nethttp_server", "reconnect"),
        ("browser_chromium", "hypercorn", "reconnect"),
        ("browser_chromium", "go_nethttp_server", "reconnect"),
        ("curl_linux", "node_http_server", "reconnect"),
        ("go_nethttp", "hypercorn", "reconnect"),
        ("java_httpclient", "node_http_server", "reconnect"),
    )
    return tuple({
        "implementation_id": f"http-{client}-{server}-{mode}",
        "client_stack": client,
        "server_stack": server,
        "connection_mode": mode,
    } for client, server, mode in pairs)


HTTP_IMPLEMENTATIONS = _http_implementations()
DNS_IMPLEMENTATIONS = tuple({
    "implementation_id": f"dns-{client}-{path}",
    "client_stack": client,
    "server_stack": "python_dns_fixture",
    "dns_path": path,
} for client in DNS_CLIENTS for path in DNS_PATHS)
WSS_IMPLEMENTATIONS = tuple({
    "implementation_id": f"wss-{client}-{server}",
    "client_stack": client,
    "server_stack": server,
    "connection_mode": "long_lived",
} for client in WSS_CLIENTS for server in WSS_SERVERS)
TUNNEL_IMPLEMENTATIONS = tuple({
    "implementation_id": f"tcp-{client}-{framing}",
    "client_stack": client,
    "server_stack": "python_bounded_duplex",
    "framing": framing,
    "connection_mode": "long_lived",
} for client in TUNNEL_CLIENTS for framing in TUNNEL_FRAMING)


def implementations_for(family_id: str) -> tuple[dict, ...]:
    if family_id in {"M-DNS-BEACON", "M-DNS-BULK"}:
        return DNS_IMPLEMENTATIONS
    if family_id == "M-WSS-LONG":
        return WSS_IMPLEMENTATIONS
    if family_id == "M-TUNNEL":
        return TUNNEL_IMPLEMENTATIONS
    if family_id == "M-HTTP-443":
        return tuple({
            "implementation_id": f"plain443-{client}",
            "client_stack": client,
            "server_stack": "python_plain_http_443",
            "connection_mode": "reconnect",
        } for client in ("python_httpx", "curl_linux", "go_nethttp", "node_fetch", "java_httpclient", "python_stdlib"))
    non_browser = tuple(x for x in HTTP_IMPLEMENTATIONS if x["client_stack"] != "browser_chromium")
    if family_id == "M-DOH":
        return tuple({**x, "doh_method": ("GET" if i % 2 else "POST")} for i, x in enumerate(non_browser[:8]))
    if family_id == "M-DEAD-DROP":
        return non_browser
    if family_id == "M-FALLBACK":
        return tuple({**x, "fallback_order": ("https_to_dns" if i % 2 == 0 else "dns_to_https")} for i, x in enumerate(non_browser[:10]))
    return HTTP_IMPLEMENTATIONS


def _payload_profile(family_id: str, n: int) -> str:
    if family_id == "M-HTTPS-LOWENT":
        return ("short_code", "guid", "fixed_hex")[n % 3]
    if family_id == "M-HTTPS-FRAG":
        return "fragment_2_6"
    if family_id.startswith("M-DNS-"):
        return ("base32_high_entropy", "fixed_hex", "short_code")[n % 3]
    return ("high_entropy_fixed", "short_code", "guid", "fragment_2_6")[n % 4]
