from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

NETWORK_PROFILES = ("clean", "wan_20ms", "wan_80ms", "lossy_wifi", "constrained")
EVENT_COUNTS = (3, 5, 10, 20, 50, 100)
JITTERS = (0.0, 0.10, 0.30)

HTTP_IMPLS = (
    "python_httpx_h1",
    "python_httpx_h2",
    "curl_h1",
    "curl_h2",
    "go_nethttp",
    "node_fetch",
    "python_stdlib",
    "chromium_fetch",
)
DNS_IMPLS = ("dnspython_udp", "raw_udp", "raw_tcp", "node_dns")
DOH_IMPLS = ("python_httpx_h2", "curl_h2", "node_fetch", "chromium_doh")
WSS_IMPLS = ("python_websockets", "python_raw_ws", "node_websocket", "chromium_websocket")
TUNNEL_IMPLS = ("python_socket", "python_asyncio", "node_net", "go_net")
DEAD_DROP_IMPLS = (
    "python_httpx_h1+curl_h1",
    "curl_h1+python_stdlib",
    "go_nethttp+node_fetch",
    "node_fetch+go_nethttp",
    "chromium_fetch+chromium_fetch",
)
SERVER_PROFILES = ("hypercorn_default", "asyncio_tls12", "asyncio_tls13")
HTTP_TRANSFER_STYLES = ("content_length", "chunked")
DOH_METHODS = ("POST", "GET")
TLS_SESSION_MODES = ("fresh", "resumption_attempt")
WS_COMPRESSION_MODES = ("none", "deflate")

FRONT_HOSTS = (
    "cdn.stage-m.test",
    "workers.stage-m.test",
    "graph.stage-m.test",
    "telegram.stage-m.test",
    "resolver.stage-m.test",
)
LOCAL_HOSTS = (
    "beacon.stage-m.test",
    "api.stage-m.test",
    "ws.stage-m.test",
    "doh.stage-m.test",
    *FRONT_HOSTS,
)


@dataclass(frozen=True)
class FamilySpec:
    family_id: str
    protocol: str
    carrier: str
    label_intent: str
    attack_mapping: tuple[str, ...]
    core_count: int
    diversity_count: int
    holdout_count: int
    implementations: tuple[str, ...]
    primary_holdout_impl: str
    payload_styles: tuple[str, ...]
    intervals: tuple[float, ...]
    direction_profiles: tuple[str, ...]
    connection_policies: tuple[str, ...] = ("reconnect", "keepalive")
    dns_topologies: tuple[str, ...] = ("direct_authoritative",)
    qtypes: tuple[str, ...] = ()
    behaviors: tuple[str, ...] = ()

    @property
    def total_count(self) -> int:
        return self.core_count + self.diversity_count + self.holdout_count


FAMILY_SPECS: tuple[FamilySpec, ...] = (
    FamilySpec(
        "M-HTTPS-BEACON", "https", "periodic_post", "c2", ("T1071.001", "T1573"),
        400, 200, 80, HTTP_IMPLS, "chromium_fetch",
        ("high_entropy_fixed", "low_entropy_code", "guid"),
        (30, 60, 300, 900, 3600),
        ("small_small", "small_large", "large_small", "alternating"),
    ),
    FamilySpec(
        "M-HTTPS-FRONT", "https", "shared_front_beacon", "c2", ("T1071.001", "T1102", "T1090"),
        400, 180, 80, HTTP_IMPLS, "chromium_fetch",
        ("high_entropy_fixed", "low_entropy_code", "guid"),
        (30, 60, 300, 900, 3600),
        ("small_small", "small_large", "large_small", "alternating"),
    ),
    FamilySpec(
        "M-HTTPS-LOWENT", "https", "low_entropy_body_or_query", "c2", ("T1071.001", "T1001.003"),
        200, 80, 40, HTTP_IMPLS, "chromium_fetch",
        ("low_entropy_code", "guid", "hex_fixed"),
        (30, 60, 300, 900),
        ("small_small", "small_large"),
    ),
    FamilySpec(
        "M-HTTPS-FRAG", "https", "short_fragment_series", "c2", ("T1071.001", "T1001.001"),
        200, 80, 40, HTTP_IMPLS, "chromium_fetch",
        ("fragment_2_6", "low_entropy_code"),
        (30, 60, 300),
        ("small_small",),
    ),
    FamilySpec(
        "M-HTTP-443", "http", "plaintext_http_on_443_or_80", "c2", ("T1071.001",),
        200, 60, 30, tuple(x for x in HTTP_IMPLS if x not in {"python_httpx_h2", "curl_h2", "chromium_fetch"}), "go_nethttp",
        ("high_entropy_fixed", "low_entropy_code", "guid"),
        (30, 60),
        ("small_small", "large_small"),
    ),
    FamilySpec(
        "M-DNS-BEACON", "dns", "periodic_dns", "c2", ("T1071.004", "T1132.001"),
        300, 130, 70, DNS_IMPLS, "node_dns",
        ("base32", "low_entropy_code", "guid"),
        (30, 60, 300, 900),
        ("query_response",),
        connection_policies=("datagram", "tcp"),
        dns_topologies=("direct_authoritative", "recursive_local"),
        qtypes=("A", "AAAA", "TXT"),
    ),
    FamilySpec(
        "M-DNS-BULK", "dns", "bulk_unique_subdomains", "exfil", ("T1071.004", "T1041", "T1132.001"),
        200, 100, 60, DNS_IMPLS, "node_dns",
        ("base32", "hex_fixed"),
        (0.05, 0.2, 1, 5),
        ("query_response",),
        connection_policies=("datagram", "tcp"),
        dns_topologies=("direct_authoritative", "recursive_local"),
        qtypes=("A", "AAAA", "TXT"),
        behaviors=("udp_only", "udp_retry", "udp_then_tcp"),
    ),
    FamilySpec(
        "M-DOH", "https", "dns_over_https", "c2", ("T1071.004", "T1071.001"),
        150, 70, 40, DOH_IMPLS, "chromium_doh",
        ("base32", "low_entropy_code"),
        (30, 60, 300),
        ("small_small",),
    ),
    FamilySpec(
        "M-DEAD-DROP", "https+https", "two_phase_dead_drop", "c2", ("T1102.001", "T1071.001"),
        200, 80, 50, DEAD_DROP_IMPLS, "chromium_fetch+chromium_fetch",
        ("low_entropy_code", "guid"),
        (1, 5, 30, 300),
        ("small_small", "small_large"),
    ),
    FamilySpec(
        "M-WSS-LONG", "wss", "long_lived_bidirectional", "c2", ("T1071.001", "T1573"),
        250, 110, 70, WSS_IMPLS, "chromium_websocket",
        ("high_entropy_fixed", "low_entropy_code", "guid"),
        (5, 30, 60, 300),
        ("small_small", "small_large", "large_small", "alternating"),
        connection_policies=("single_long_connection", "reconnect"),
        behaviors=("idle", "small_duplex", "rare_large", "fragmented", "ping_pong"),
    ),
    FamilySpec(
        "M-TUNNEL", "tcp", "bounded_bidirectional_tunnel_shape", "tunnel", ("T1572", "T1090"),
        200, 100, 60, TUNNEL_IMPLS, "go_net",
        ("high_entropy_fixed", "low_entropy_code"),
        (0.01, 0.05, 0.2, 1),
        ("symmetric", "upload_80_20", "download_20_80", "burst_idle", "steady_duplex"),
        connection_policies=("single_long_connection", "reconnect"),
        behaviors=("len16", "len32", "newline", "fixed64"),
    ),
    FamilySpec(
        "M-FALLBACK", "https+dns", "transport_fallback", "c2", ("T1071.001", "T1071.004"),
        150, 60, 50, ("python_httpx_h1+dnspython_udp", "curl_h1+raw_udp", "node_fetch+node_dns"), "node_fetch+node_dns",
        ("low_entropy_code", "guid"),
        (1, 5, 30, 300),
        ("small_small",),
        dns_topologies=("direct_authoritative", "recursive_local"),
        qtypes=("A", "AAAA", "TXT"),
        behaviors=("https_to_dns_early", "https_to_dns_mid", "https_to_dns_late", "dns_to_https_early", "dns_to_https_mid", "dns_to_https_late"),
    ),
    FamilySpec(
        "M-RMM-SHAPE", "http+https", "poll_then_interactive_burst", "c2", ("T1219", "T1071.001"),
        100, 50, 30, HTTP_IMPLS, "chromium_fetch",
        ("low_entropy_code", "guid"),
        (30, 60, 300),
        ("small_small", "alternating", "small_large"),
        behaviors=("short_burst", "medium_burst", "asymmetric_burst"),
    ),
)

BY_FAMILY = {s.family_id: s for s in FAMILY_SPECS}


@dataclass(frozen=True)
class CampaignPlan:
    campaign_id: str
    family_id: str
    tier: str
    implementation_id: str
    primary_split: str
    network_profile: str
    nominal_interval_seconds: float
    jitter_fraction: float
    event_count_target: int
    payload_style: str
    direction_profile: str
    connection_policy: str
    front_host: str
    dns_topology: str
    qtype: str
    behavior_profile: str
    server_impl: str
    tls_profile: str
    tls_session_mode: str
    http_transfer_style: str
    doh_method: str
    ws_compression: str
    seed: int
    index_in_family: int

    def to_dict(self) -> dict:
        return asdict(self)


def _choose(seq: tuple[str, ...] | tuple[float, ...] | tuple[int, ...], n: int):
    return seq[n % len(seq)]


def _tier_counts(spec: FamilySpec) -> tuple[tuple[str, int], ...]:
    return (("core", spec.core_count), ("diversity", spec.diversity_count), ("holdout", spec.holdout_count))


def iter_campaigns(seed: int = 26092301) -> Iterable[CampaignPlan]:
    global_index = 0
    for spec in FAMILY_SPECS:
        train_impls = tuple(x for x in spec.implementations if x != spec.primary_holdout_impl)
        if not train_impls:
            train_impls = spec.implementations
        family_index = 0
        for tier, count in _tier_counts(spec):
            impls = (spec.primary_holdout_impl,) if tier == "holdout" else train_impls
            for local_i in range(count):
                n = family_index + local_i
                impl = _choose(impls, n * 7 + global_index * 3)
                network = _choose(NETWORK_PROFILES, n * 11 + global_index)
                interval = _choose(spec.intervals, n * 13 + global_index)
                jitter = _choose(JITTERS, n * 17 + global_index)
                event_count = _choose(EVENT_COUNTS, n * 19 + global_index)
                payload = _choose(spec.payload_styles, n * 23 + global_index)
                direction = _choose(spec.direction_profiles, n * 29 + global_index)
                conn = _choose(spec.connection_policies, n * 31 + global_index)
                if spec.protocol == "dns":
                    conn = "tcp" if impl == "raw_tcp" else "datagram"
                front = _choose(FRONT_HOSTS, n * 37 + global_index) if spec.family_id == "M-HTTPS-FRONT" else "beacon.stage-m.test"
                dns_topology = _choose(spec.dns_topologies, n * 41 + global_index)
                qtype = _choose(spec.qtypes, n * 43 + global_index) if spec.qtypes else ""
                behavior = _choose(spec.behaviors, n * 47 + global_index) if spec.behaviors else ""
                http_impl = str(impl).split("+", 1)[0]
                if spec.protocol in {"https", "https+https", "https+dns", "http+https", "http"} and spec.family_id != "M-WSS-LONG":
                    if "chromium" in http_impl:
                        conn = "keepalive"
                    elif http_impl in {"python_httpx_h1", "python_httpx_h2"}:
                        conn = _choose(("reconnect", "keepalive"), n * 31 + global_index)
                    else:
                        conn = "reconnect"
                if spec.family_id == "M-HTTP-443":
                    server_impl = "hypercorn_plain"
                elif spec.protocol in {"https", "https+https", "https+dns", "http+https"}:
                    if "h2" in http_impl or "chromium" in http_impl:
                        server_impl = "hypercorn_default"
                    else:
                        server_impl = _choose(SERVER_PROFILES, n * 53 + global_index)
                else:
                    server_impl = "local_protocol_fixture"
                tls_profile = {"asyncio_tls12": "tls12", "asyncio_tls13": "tls13"}.get(str(server_impl), "default")
                if http_impl == "python_stdlib" and tls_profile in {"tls12", "tls13"}:
                    tls_session_mode = _choose(TLS_SESSION_MODES, n * 59 + global_index)
                else:
                    tls_session_mode = "fresh"
                transfer_style = _choose(HTTP_TRANSFER_STYLES, n * 61 + global_index)
                doh_method = _choose(DOH_METHODS, n * 67 + global_index) if spec.family_id == "M-DOH" else ""
                if spec.family_id == "M-WSS-LONG" and str(impl) in {"python_websockets", "chromium_websocket"}:
                    ws_compression = _choose(WS_COMPRESSION_MODES, n * 71 + global_index)
                else:
                    ws_compression = "none"
                if spec.family_id == "M-WSS-LONG":
                    server_impl = "websockets_deflate" if ws_compression == "deflate" else "websockets_plain"
                    tls_profile = "default"
                cid = f"m-{spec.family_id[2:].lower()}-{tier[0]}-{n:05d}"
                yield CampaignPlan(
                    campaign_id=cid,
                    family_id=spec.family_id,
                    tier=tier,
                    implementation_id=str(impl),
                    primary_split="implementation_holdout" if tier == "holdout" else "train_candidate",
                    network_profile=str(network),
                    nominal_interval_seconds=float(interval),
                    jitter_fraction=float(jitter),
                    event_count_target=int(event_count),
                    payload_style=str(payload),
                    direction_profile=str(direction),
                    connection_policy=str(conn),
                    front_host=str(front),
                    dns_topology=str(dns_topology),
                    qtype=str(qtype),
                    behavior_profile=str(behavior),
                    server_impl=str(server_impl),
                    tls_profile=str(tls_profile),
                    tls_session_mode=str(tls_session_mode),
                    http_transfer_style=str(transfer_style),
                    doh_method=str(doh_method),
                    ws_compression=str(ws_compression),
                    seed=seed + global_index * 1009 + n,
                    index_in_family=n,
                )
                global_index += 1
            family_index += count


def build_split_summary(plans: Iterable[CampaignPlan]) -> dict:
    rows = list(plans)
    dimensions = {
        "implementation_id": sorted({x.implementation_id for x in rows}),
        "network_profile": sorted({x.network_profile for x in rows}),
        "payload_style": sorted({x.payload_style for x in rows}),
        "nominal_interval_seconds": sorted({x.nominal_interval_seconds for x in rows}),
        "server_impl": sorted({x.server_impl for x in rows}),
        "tls_profile": sorted({x.tls_profile for x in rows}),
    }
    folds = []
    for spec in FAMILY_SPECS:
        family_rows = [x for x in rows if x.family_id == spec.family_id]
        for impl in spec.implementations:
            test = sum(x.implementation_id == impl for x in family_rows)
            train = len(family_rows) - test
            if test:
                folds.append({"dimension": "implementation_id", "family_id": spec.family_id, "held_out": impl, "train_count": train, "test_count": test})
    for dim in ("network_profile", "payload_style", "nominal_interval_seconds", "server_impl", "tls_profile"):
        for value in dimensions[dim]:
            test = sum(getattr(x, dim) == value for x in rows)
            folds.append({"dimension": dim, "held_out": value, "train_count": len(rows)-test, "test_count": test})
    return {
        "schema_version": 1,
        "positive_only": True,
        "campaign_count": len(rows),
        "family_count": len(FAMILY_SPECS),
        "primary_train_candidate_count": sum(x.primary_split == "train_candidate" for x in rows),
        "primary_implementation_holdout_count": sum(x.primary_split == "implementation_holdout" for x in rows),
        "dimensions": dimensions,
        "folds": folds,
    }


def validate_plan(plans: Iterable[CampaignPlan]) -> dict:
    rows = list(plans)
    errors: list[str] = []
    ids = [x.campaign_id for x in rows]
    if len(ids) != len(set(ids)):
        errors.append("duplicate campaign_id")
    expected = sum(x.total_count for x in FAMILY_SPECS)
    if len(rows) != expected:
        errors.append(f"campaign_count={len(rows)} expected={expected}")
    if expected != 4950:
        errors.append(f"catalog total changed: {expected} != 4950")
    for spec in FAMILY_SPECS:
        fr = [x for x in rows if x.family_id == spec.family_id]
        if len(fr) != spec.total_count:
            errors.append(f"{spec.family_id}: count {len(fr)} != {spec.total_count}")
        hold = [x for x in fr if x.primary_split == "implementation_holdout"]
        if len(hold) != spec.holdout_count:
            errors.append(f"{spec.family_id}: holdout count {len(hold)} != {spec.holdout_count}")
        if any(x.implementation_id != spec.primary_holdout_impl for x in hold):
            errors.append(f"{spec.family_id}: holdout implementation contamination")
        train = [x for x in fr if x.primary_split == "train_candidate"]
        if any(x.implementation_id == spec.primary_holdout_impl for x in train):
            errors.append(f"{spec.family_id}: primary holdout implementation leaked into train_candidate")
    if not all(x.front_host.endswith(".stage-m.test") for x in rows):
        errors.append("non-local front host detected")
    return {
        "passed": not errors,
        "errors": errors,
        "campaign_count": len(rows),
        "family_counts": {s.family_id: sum(x.family_id == s.family_id for x in rows) for s in FAMILY_SPECS},
        "implementation_count": len({(x.family_id, x.implementation_id) for x in rows}),
        "network_profiles": sorted({x.network_profile for x in rows}),
        "positive_only": True,
    }


if __name__ == "__main__":
    import json
    rows = list(iter_campaigns())
    print(json.dumps({"validation": validate_plan(rows), "splits": build_split_summary(rows)}, indent=2, sort_keys=True))
