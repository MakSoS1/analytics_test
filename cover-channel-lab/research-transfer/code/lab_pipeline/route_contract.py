"""Identity and conservative classification for the multi-route detector.

Route selection is deliberately based on transport facts, not model scores.  An
unknown UDP, DNS, ICMP, or ESP observation is never made to look like a TCP/TLS
fast-v1 feature vector simply because that is the only trained model today.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from lab_pipeline.flow_tier import FLOW_TIER_FEATURES
from lab_pipeline.online_schema import FEATURE_NAMES, SCHEMA_VERSION, contract_hash


RouteName = Literal["tcp_tls_fast", "quic_udp", "special_transport"]
# Three, not four. `classify_route` sends every TCP flow to tcp_tls_fast and
# every UDP flow to quic_udp, so a fourth "opaque" route could only ever be the
# fallback for a protocol that is neither — it received 1 tunnel flow out of
# 10 953 in the corpus. Making it reachable needs an app-layer split (TLS
# opening or not), and that was measured: identical at loose FPR budgets, and at
# 3e-4 it drops a family to 0.000 recall where three routes hold 0.333. The
# release gate is a floor on every family, so the split loses.
ROUTES: tuple[RouteName, ...] = (
    "tcp_tls_fast", "quic_udp", "special_transport",
)


@dataclass(frozen=True)
class RouteSpec:
    route: RouteName
    schema_version: str
    features: tuple[str, ...]
    contract_hash: str


# The three routes fed by the fast-v1 reducer observe the SAME vector: the
# reducer computes all 103 features for any TCP or UDP flow it sees, so the
# four-to-six aggregate columns the skeleton started with threw away the
# per-packet length, direction and timing prefix that is where the separation
# actually lives.
#
# special_transport is different, and not by preference. The fast-v1 contract
# deliberately excludes DNS (OUT_OF_SCOPE_PORTS) and has no ICMP flow key, so
# `extract_special_flow_features.py` exists to build that corpus with the
# counter-only flow-tier set instead. Declaring the 103-feature vector here
# would name columns that extractor cannot produce.
#
# Every route still keeps its own schema_version and contract hash, so a model
# trained for one route cannot be loaded into another even where columns match.
_ROUTE_FEATURES: dict[RouteName, tuple[str, ...]] = {
    "tcp_tls_fast": tuple(FEATURE_NAMES),
    "quic_udp": tuple(FEATURE_NAMES),
    "special_transport": tuple(FLOW_TIER_FEATURES),
}


def _route_hash(route: RouteName, schema_version: str, features: tuple[str, ...]) -> str:
    payload = json.dumps({"route": route, "schema_version": schema_version,
                          "features": list(features)}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _make_spec(route: RouteName) -> RouteSpec:
    features = _ROUTE_FEATURES[route]
    if route == "tcp_tls_fast":
        return RouteSpec(route, SCHEMA_VERSION, features, contract_hash())
    schema_version = f"{route}-v1"
    return RouteSpec(route, schema_version, features, _route_hash(route, schema_version, features))


_SPECS: dict[RouteName, RouteSpec] = {route: _make_spec(route) for route in ROUTES}


def route_spec(route: RouteName) -> RouteSpec:
    """Return immutable schema identity for a known detector route."""
    try:
        return _SPECS[route]
    except KeyError as exc:
        raise ValueError(f"unknown detector route: {route!r}") from exc


def _protocol(observation: dict[str, object]) -> str:
    raw = observation.get("proto", observation.get("protocol", ""))
    if isinstance(raw, int):
        return {1: "icmp", 50: "esp", 58: "icmpv6", 6: "tcp", 17: "udp"}.get(raw, str(raw))
    return str(raw or "").strip().lower()


def _port(value: object) -> int | None:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def classify_route(observation: dict[str, object]) -> RouteName:
    """Choose a route without letting unrecognised transport reach fast-v1."""
    proto = _protocol(observation)
    ports = {_port(observation.get("src_port")), _port(observation.get("dst_port"))}
    if proto in {"icmp", "icmpv6", "esp", "50", "1", "58"}:
        return "special_transport"
    if ports & {53, 5353}:
        return "special_transport"
    if proto == "udp" or observation.get("quic") is True:
        return "quic_udp"
    if proto == "tcp":
        return "tcp_tls_fast"
    # Anything that is neither TCP nor UDP belongs with the other non-stream
    # transports, which is what special_transport is for. Routing it to a
    # residual "opaque" model would be routing it to a model with no training
    # data for it.
    return "special_transport"
