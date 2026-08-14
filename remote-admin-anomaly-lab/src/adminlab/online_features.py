from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Any

WINDOWS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}


def _missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float):
        return math.isnan(value) or math.isinf(value)
    return False


def _epoch(value: Any) -> float:
    if _missing(value):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()
    except (ValueError, OverflowError):
        return 0.0


def _text(value: Any) -> str:
    return "" if _missing(value) else str(value)


def _number(value: Any) -> float:
    if _missing(value):
        return 0.0
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return numeric if math.isfinite(numeric) else 0.0


def _integer(value: Any) -> int:
    return int(_number(value))


def _entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    return 0.0 if not total else float(-sum((n / total) * math.log2(n / total) for n in counter.values() if n))


def _clock(ts: float) -> tuple[float, float, int]:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    seconds = dt.hour * 3600 + dt.minute * 60 + dt.second
    angle = 2.0 * math.pi * seconds / 86400.0
    return math.sin(angle), math.cos(angle), int(dt.weekday() >= 5)


class EveFeatureState:
    """Stateful production feature extractor for Suricata EVE flow events.

    Raw IPs are retained only as state keys and returned in `context`; they are
    never part of the model feature dictionary. All history values are prior-only:
    the current event is appended after feature calculation.
    """

    def __init__(self) -> None:
        self.history: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.seen_dst: dict[str, set[str]] = defaultdict(set)
        self.pair_seen: Counter[tuple[str, str]] = Counter()
        self.graph: deque[tuple[float, str, str, bool]] = deque()
        self.out_edges: dict[str, Counter[str]] = defaultdict(Counter)
        self.in_edges: dict[str, Counter[str]] = defaultdict(Counter)
        self.new_edges: Counter[str] = Counter()
        self.ever_edges: set[tuple[str, str]] = set()

    def consume_flow(self, event: dict[str, Any]) -> dict[str, Any]:
        if event.get("event_type") != "flow":
            raise ValueError("EVE event_type must be flow")
        src = _text(event.get("src_ip"))
        dst = _text(event.get("dest_ip"))
        dport = _integer(event.get("dest_port"))
        app_proto = event.get("app_proto")
        network_proto = event.get("proto")
        proto = _text(app_proto) if not _missing(app_proto) and _text(app_proto) else (_text(network_proto) or "unknown")
        ts = _epoch(event.get("timestamp"))
        flow = event.get("flow")
        if not isinstance(flow, dict):
            flow = {}

        hist = self.history[src]
        while hist and hist[0][0] < ts - WINDOWS["30d"]:
            hist.popleft()
        history = list(hist)

        def recent(seconds: int):
            return [entry for entry in history if entry[0] >= ts - seconds]

        h60 = recent(WINDOWS["1m"])
        h300 = recent(WINDOWS["5m"])
        h900 = recent(WINDOWS["15m"])
        h1h = recent(WINDOWS["1h"])
        h24 = recent(WINDOWS["24h"])
        h7 = recent(WINDOWS["7d"])
        h30 = history

        pair = (src, dst)
        new_dst = dst not in self.seen_dst[src]
        new_pair = self.pair_seen[pair] == 0

        def pair_count(events):
            return sum(1 for entry in events if entry[1] == dst)

        while self.graph and self.graph[0][0] < ts - WINDOWS["1h"]:
            _, source, destination, was_new = self.graph.popleft()
            self.out_edges[source][destination] -= 1
            self.in_edges[destination][source] -= 1
            if self.out_edges[source][destination] <= 0:
                del self.out_edges[source][destination]
            if self.in_edges[destination][source] <= 0:
                del self.in_edges[destination][source]
            if was_new:
                self.new_edges[source] -= 1

        src_b = _number(flow.get("bytes_toserver"))
        dst_b = _number(flow.get("bytes_toclient"))
        src_p = _number(flow.get("pkts_toserver"))
        dst_p = _number(flow.get("pkts_toclient"))
        start = _epoch(flow.get("start"))
        end = _epoch(flow.get("end"))
        duration = max(0.0, end - start)
        hour_sin, hour_cos, is_weekend = _clock(ts)

        features = {
            "flow_count": 1,
            "duration": duration,
            "src_bytes": src_b,
            "dst_bytes": dst_b,
            "src_packets": src_p,
            "dst_packets": dst_p,
            "bytes_total": src_b + dst_b,
            "packets_total": src_p + dst_p,
            "bytes_ratio": src_b / (dst_b + 1.0),
            "packets_ratio": src_p / (dst_p + 1.0),
            "app_proto": proto,
            "dst_port": dport,
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "is_weekend": is_weekend,
            "connections_1m": len(h60),
            "connections_5m": len(h300),
            "connections_15m": len(h900),
            "connections_1h": len(h1h),
            "connections_24h": len(h24),
            "connections_7d": len(h7),
            "connections_30d": len(h30),
            "unique_dst_ip_5m": len({entry[1] for entry in h300}),
            "unique_dst_ip_15m": len({entry[1] for entry in h900}),
            "unique_dst_ip_24h": len({entry[1] for entry in h24}),
            "unique_dst_ip_7d": len({entry[1] for entry in h7}),
            "unique_dst_ip_30d": len({entry[1] for entry in h30}),
            "unique_protocols_1h": len({entry[2] for entry in h1h}),
            "new_dst_for_src": int(new_dst),
            "new_src_dst_pair": int(new_pair),
            "new_dst_24h": int(pair_count(h24) == 0),
            "new_dst_7d": int(pair_count(h7) == 0),
            "new_dst_30d": int(pair_count(h30) == 0),
            "pair_seen_count": int(self.pair_seen[pair]),
            "pair_connections_24h": pair_count(h24),
            "pair_connections_7d": pair_count(h7),
            "pair_connections_30d": pair_count(h30),
            "src_out_degree_1h": len(self.out_edges[src]),
            "dst_in_degree_1h": len(self.in_edges[dst]),
            "new_edge_count_1h": int(self.new_edges[src]),
            "protocol_entropy_1h": _entropy(Counter(entry[2] for entry in h1h)),
            "protocol_entropy_24h": _entropy(Counter(entry[2] for entry in h24)),
        }

        was_new = pair not in self.ever_edges
        hist.append((ts, dst, proto))
        self.seen_dst[src].add(dst)
        self.pair_seen[pair] += 1
        self.ever_edges.add(pair)
        self.graph.append((ts, src, dst, was_new))
        self.out_edges[src][dst] += 1
        self.in_edges[dst][src] += 1
        if was_new:
            self.new_edges[src] += 1

        return {
            "features": features,
            "context": {
                "timestamp": event.get("timestamp"),
                "flow_id": event.get("flow_id"),
                "src_ip": src,
                "dest_ip": dst,
                "dest_port": dport,
                "app_proto": proto,
            },
        }
