from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

WINDOWS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}


def _num(row: dict[str, Any], name: str) -> float:
    value = row.get(name, 0)
    try:
        return 0.0 if value in (None, "-", "") else float(value)
    except (TypeError, ValueError):
        return 0.0


def _entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if not total:
        return 0.0
    return float(-sum((n / total) * math.log2(n / total) for n in counter.values() if n))


@dataclass
class ProductionFlowState:
    source_history: dict[str, deque[tuple[float, str, str]]] = field(default_factory=lambda: defaultdict(deque))
    seen_dst: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    pair_seen: Counter[tuple[str, str]] = field(default_factory=Counter)
    graph: deque[tuple[float, str, str, bool]] = field(default_factory=deque)
    out_edges: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    in_edges: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    new_edges: Counter[str] = field(default_factory=Counter)
    ever_edges: set[tuple[str, str]] = field(default_factory=set)

    def process(self, frame: pd.DataFrame) -> pd.DataFrame:
        required = {"session_id", "id.orig_h", "id.resp_h", "id.resp_p"}
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(f"mapped conn missing: {sorted(missing)}")
        time_col = "behavior_ts" if "behavior_ts" in frame.columns else "ts"
        if time_col not in frame.columns:
            raise ValueError("mapped conn requires behavior_ts or ts")
        rows = frame.sort_values([time_col, "session_id"]).to_dict("records")
        output: list[dict[str, Any]] = []
        for idx, row in enumerate(rows):
            ts = _num(row, time_col); src = str(row["id.orig_h"]); dst = str(row["id.resp_h"]); dport = int(_num(row, "id.resp_p")); proto = str(row.get("service") or row.get("proto") or "unknown"); sid = str(row["session_id"])
            hist = self.source_history[src]
            while hist and hist[0][0] < ts - WINDOWS["30d"]:
                hist.popleft()
            history = list(hist)
            def recent(seconds: int): return [e for e in history if e[0] >= ts - seconds]
            h60, h300, h900, h1h = recent(WINDOWS["1m"]), recent(WINDOWS["5m"]), recent(WINDOWS["15m"]), recent(WINDOWS["1h"])
            h24, h7, h30 = recent(WINDOWS["24h"]), recent(WINDOWS["7d"]), history
            pair = (src, dst)
            def pc(events): return sum(1 for e in events if e[1] == dst)
            while self.graph and self.graph[0][0] < ts - WINDOWS["1h"]:
                _, osrc, odst, was_new = self.graph.popleft(); self.out_edges[osrc][odst] -= 1; self.in_edges[odst][osrc] -= 1
                if self.out_edges[osrc][odst] <= 0: del self.out_edges[osrc][odst]
                if self.in_edges[odst][osrc] <= 0: del self.in_edges[odst][osrc]
                if was_new: self.new_edges[osrc] -= 1
            ob, rb, op, rp = _num(row, "orig_bytes"), _num(row, "resp_bytes"), _num(row, "orig_pkts"), _num(row, "resp_pkts")
            uid = str(row.get("uid") or f"flow-{idx:012d}")
            output.append({
                "flow_uid": uid, "session_id": sid,
                "flow_count": 1, "duration": _num(row, "duration"), "src_bytes": ob, "dst_bytes": rb, "src_packets": op, "dst_packets": rp,
                "bytes_total": ob + rb, "packets_total": op + rp, "bytes_ratio": ob / (rb + 1.0), "packets_ratio": op / (rp + 1.0), "app_proto": proto, "dst_port": dport,
                "connections_1m": len(h60), "connections_5m": len(h300), "connections_15m": len(h900), "connections_1h": len(h1h),
                "connections_24h": len(h24), "connections_7d": len(h7), "connections_30d": len(h30),
                "unique_dst_ip_5m": len({e[1] for e in h300}), "unique_dst_ip_15m": len({e[1] for e in h900}),
                "unique_dst_ip_24h": len({e[1] for e in h24}), "unique_dst_ip_7d": len({e[1] for e in h7}), "unique_dst_ip_30d": len({e[1] for e in h30}),
                "unique_protocols_1h": len({e[2] for e in h1h}),
                "new_dst_for_src": int(dst not in self.seen_dst[src]), "new_src_dst_pair": int(self.pair_seen[pair] == 0),
                "new_dst_24h": int(pc(h24) == 0), "new_dst_7d": int(pc(h7) == 0), "new_dst_30d": int(pc(h30) == 0),
                "pair_seen_count": int(self.pair_seen[pair]), "pair_connections_24h": pc(h24), "pair_connections_7d": pc(h7), "pair_connections_30d": pc(h30),
                "src_out_degree_1h": len(self.out_edges[src]), "dst_in_degree_1h": len(self.in_edges[dst]), "new_edge_count_1h": int(self.new_edges[src]),
                "protocol_entropy_1h": _entropy(Counter(e[2] for e in h1h)), "protocol_entropy_24h": _entropy(Counter(e[2] for e in h24)),
            })
            was_new = pair not in self.ever_edges; hist.append((ts, dst, proto)); self.seen_dst[src].add(dst); self.pair_seen[pair] += 1; self.ever_edges.add(pair); self.graph.append((ts, src, dst, was_new)); self.out_edges[src][dst] += 1; self.in_edges[dst][src] += 1
            if was_new: self.new_edges[src] += 1
        return pd.DataFrame(output)


def build_production_flow_features(mapped_conn: pd.DataFrame) -> pd.DataFrame:
    return ProductionFlowState().process(mapped_conn)


def build_split_isolated_production_flow_features(mapped_conn: pd.DataFrame) -> pd.DataFrame:
    if "split" not in mapped_conn.columns:
        raise ValueError("split column required for isolated state computation")
    chunks: list[pd.DataFrame] = []
    preferred = ["train", "validation", "test", "challenge"]
    splits = preferred + sorted(set(mapped_conn["split"].astype(str)) - set(preferred))
    for split in splits:
        subset = mapped_conn[mapped_conn["split"].astype(str) == split]
        if subset.empty:
            continue
        # Deliberately fresh state per dataset partition. This is conservative,
        # but guarantees validation/test/challenge can never influence train or
        # each other. A separately generated baseline warm-up may be loaded in a
        # future version without crossing labelled partition boundaries.
        part = ProductionFlowState().process(subset)
        part["_split_for_order"] = split
        chunks.append(part)
    if not chunks:
        return pd.DataFrame()
    result = pd.concat(chunks, ignore_index=True)
    order = {str(uid): i for i, uid in enumerate(mapped_conn.get("uid", pd.Series(dtype=str)).astype(str).tolist())}
    result["_order"] = result["flow_uid"].map(order).fillna(len(order))
    return result.sort_values("_order").drop(columns=["_order", "_split_for_order"], errors="ignore").reset_index(drop=True)
