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

def _event_count(family_id: str, interval: int, n: int) -> int:
    if family_id == "M-DNS-BULK":
        return (20, 50, 100)[n % 3]
    if family_id == "M-TUNNEL":
        return (10, 20, 50, 100)[n % 4]
    if family_id == "M-WSS-LONG":
        return (5, 10, 20, 50, 100)[n % 5]
    if interval >= 900:
        return (3, 5)[n % 2]
    if interval >= 300:
        return (3, 5, 10)[n % 3]
    return EVENT_COUNTS[n % len(EVENT_COUNTS)]


def _tier_records(family: StageMFamily) -> Iterable[tuple[str, int]]:
    yield "core", family.core_count
    if family.diversity_count:
        yield "implementation_diversity", family.diversity_count
    if family.holdout_count:
        yield "implementation_holdout", family.holdout_count


def campaign_plan(seed: int = 26092301) -> list[dict]:
    out: list[dict] = []
    global_index = 0
    for family in FAMILIES:
        family_index = 0
        implementations = implementations_for(family.family_id)
        for tier, count in _tier_records(family):
            for _ in range(count):
                h = _stable_int(seed, family.family_id, family_index, tier)
                impl = dict(implementations[h % len(implementations)])
                interval = NOMINAL_INTERVAL_SECONDS[(h // 7) % len(NOMINAL_INTERVAL_SECONDS)]
                jitter = JITTER_FRACTIONS[(h // 17) % len(JITTER_FRACTIONS)]
                network = NETWORK_PROFILES[(h // 29) % len(NETWORK_PROFILES)]
                payload = _payload_profile(family.family_id, h)
                direction = DIRECTION_PROFILES[(h // 43) % len(DIRECTION_PROFILES)]
                event_count = _event_count(family.family_id, interval, h)
                front = FRONT_HOSTS[(h // 53) % len(FRONT_HOSTS)]
                qtype = ("A", "AAAA", "TXT")[(h // 61) % 3]
                dns_transport = ("udp", "tcp")[(h // 67) % 2]
                nx_ratio = (0.0, 0.10, 0.50)[(h // 71) % 3]
                requested_tls = ("native", "tls12", "tls13")[(h // 79) % 3]
                tls_profile = requested_tls if impl.get("client_stack") in {"python_httpx", "python_httpx_h2"} else "native"
                cid = f"m-{global_index:05d}"
                record = {
                    "campaign_index": global_index,
                    "family_index": family_index,
                    "campaign_id": cid,
                    "family_id": family.family_id,
                    "transport": family.transport,
                    "tier": tier,
                    "dataset_role": "positive_implementation_holdout" if tier == "implementation_holdout" else "positive_cover_channel",
                    "training_eligible": tier != "implementation_holdout",
                    "stage_m_split_role": "implementation_holdout" if tier == "implementation_holdout" else ("diversity" if tier == "implementation_diversity" else "train_candidate"),
                    "attack_mapping": list(family.attack_mapping),
                    "network_profile": network,
                    "nominal_interval_seconds": interval,
                    "jitter_fraction": jitter,
                    "event_count_target": event_count,
                    "payload_profile": payload,
                    "direction_profile": direction,
                    "front_host": front,
                    "dns_qtype": qtype,
                    "dns_transport": dns_transport,
                    "dns_nxdomain_ratio": nx_ratio,
                    "tls_profile": tls_profile,
                    "requested_tls_profile": requested_tls,
                    **impl,
                }
                if family.family_id == "M-FALLBACK":
                    record["dns_path"] = DNS_PATHS[(h // 83) % len(DNS_PATHS)]
                    record["dns_qtype"] = ("A", "AAAA", "TXT")[(h // 89) % 3]
                    record["dns_transport"] = ("udp", "tcp")[(h // 97) % 2]
                record["holdout_groups"] = {
                    "implementation": record["implementation_id"],
                    "client": record["client_stack"],
                    "server": record["server_stack"],
                    "network": network,
                    "timing": f"{interval}s-j{int(jitter*100)}",
                    "payload": payload,
                }
                out.append(record)
                family_index += 1
                global_index += 1
    assert_plan(out)
    return out


def assert_plan(plan: list[dict]) -> None:
    if len(plan) != EXPECTED_TOTAL_CAMPAIGNS:
        raise ValueError(f"Stage M plan size {len(plan)} != {EXPECTED_TOTAL_CAMPAIGNS}")
    ids = [x["campaign_id"] for x in plan]
    if len(ids) != len(set(ids)):
        raise ValueError("Stage M campaign IDs are not unique")
    for family in FAMILIES:
        rows = [x for x in plan if x["family_id"] == family.family_id]
        if len(rows) != family.total_count:
            raise ValueError(f"{family.family_id}: expected {family.total_count}, got {len(rows)}")
        min_impl = 3 if family.family_id not in {"M-RMM-SHAPE"} else 2
        if len({x["implementation_id"] for x in rows}) < min_impl:
            raise ValueError(f"{family.family_id}: insufficient implementation diversity")
    if {x["network_profile"] for x in plan} != set(NETWORK_PROFILES):
        raise ValueError("Stage M does not cover every real netem profile")
    if not set(EVENT_COUNTS[:4]).issubset({x["event_count_target"] for x in plan}):
        raise ValueError("Stage M event-count diversity collapsed")
    if any(not str(x["front_host"]).endswith(".test") for x in plan):
        raise ValueError("Stage M contains a non-local front host")


def plan_summary(plan: list[dict] | None = None) -> dict:
    plan = campaign_plan() if plan is None else plan
    by_family = {}
    for family in FAMILIES:
        rows = [x for x in plan if x["family_id"] == family.family_id]
        by_family[family.family_id] = {
            "campaigns": len(rows),
            "implementations": len({x["implementation_id"] for x in rows}),
            "clients": sorted({x["client_stack"] for x in rows}),
            "servers": sorted({x["server_stack"] for x in rows}),
        }
    return {
        "contract_revision": 1,
        "positive_only": True,
        "campaigns": len(plan),
        "families": by_family,
        "network_profiles": sorted({x["network_profile"] for x in plan}),
        "event_counts": sorted({x["event_count_target"] for x in plan}),
        "nominal_intervals_seconds": sorted({x["nominal_interval_seconds"] for x in plan}),
        "jitter_fractions": sorted({x["jitter_fraction"] for x in plan}),
    }
