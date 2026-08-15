from __future__ import annotations

import bisect
import json
import math
import subprocess
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import pandas as pd

from .wire_paths import expand_sessions_for_wire_mapping

WINDOWS = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}


def read_zstd_json_lines(path: Path | str) -> pd.DataFrame:
    proc = subprocess.run(["zstd", "-q", "-dc", str(Path(path))], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return pd.DataFrame([json.loads(line) for line in proc.stdout.splitlines() if line.strip()])


def _epoch(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True).astype("int64") / 1_000_000_000.0


def _conn_key(row: pd.Series | dict[str, Any]) -> tuple[str, str, int]:
    return str(row.get("id.orig_h", "")), str(row.get("id.resp_h", "")), int(row.get("id.resp_p", 0) or 0)


def _mapping_time_columns(sessions: pd.DataFrame) -> tuple[str, str, str]:
    required = {"execution_start_ts", "execution_end_ts"}
    if required <= set(sessions.columns):
        starts = sessions["execution_start_ts"].fillna("").astype(str).str.strip()
        ends = sessions["execution_end_ts"].fillna("").astype(str).str.strip()
        if starts.ne("").all() and ends.ne("").all():
            return "execution_start_ts", "execution_end_ts", "execution_start_ts/execution_end_ts"
    return "start_ts", "end_ts", "start_ts/end_ts_legacy"


def map_zeek_flows_to_sessions(sessions: pd.DataFrame, conn: pd.DataFrame, *, tolerance_seconds: float = 2.0) -> tuple[pd.DataFrame, dict[str, Any]]:
    required_sessions = {"session_id", "src_ip", "dst_ip", "dst_port", "start_ts", "end_ts"}
    missing = required_sessions - set(sessions.columns)
    if missing: raise ValueError(f"sessions missing required columns: {sorted(missing)}")
    required_conn = {"ts", "id.orig_h", "id.resp_h", "id.resp_p"}
    missing_conn = required_conn - set(conn.columns)
    if missing_conn: raise ValueError(f"conn log missing required columns: {sorted(missing_conn)}")

    # Preserve logical session identity/history while expanding only the
    # correspondence view into expected wire hops.  Most sessions have one hop;
    # bounded approved SSH forwarding has client->jump and jump->target legs.
    original = sessions.copy().reset_index(drop=True)
    start_col, end_col, time_source = _mapping_time_columns(original)
    s = expand_sessions_for_wire_mapping(original).reset_index(drop=True)
    s["_start"] = _epoch(s[start_col]); s["_end"] = _epoch(s[end_col])

    groups: dict[tuple[str, str, int], tuple[list[float], list[dict[str, Any]]]] = {}
    for key, frame in s.groupby(["src_ip", "dst_ip", "dst_port"], sort=False):
        ordered = frame.sort_values("_start")
        groups[(str(key[0]), str(key[1]), int(key[2]))] = (ordered["_start"].astype(float).tolist(), ordered.to_dict("records"))
    mapped: list[dict[str, Any]] = []; unmapped = 0
    for row in conn.to_dict("records"):
        group = groups.get(_conn_key(row))
        if group is None: unmapped += 1; continue
        ts = float(row.get("ts", 0.0) or 0.0); starts, records = group; pos = bisect.bisect_right(starts, ts + tolerance_seconds) - 1; best = None; best_distance = float("inf")
        for idx in range(pos, max(-1, pos - 24), -1):
            if idx < 0: break
            candidate = records[idx]
            if float(candidate["_end"]) + tolerance_seconds < ts: break
            if float(candidate["_start"]) - tolerance_seconds <= ts <= float(candidate["_end"]) + tolerance_seconds:
                midpoint = (float(candidate["_start"]) + float(candidate["_end"])) / 2.0; distance = abs(ts - midpoint)
                if distance < best_distance: best = candidate; best_distance = distance
        if best is None: unmapped += 1; continue
        out = dict(row); out["session_id"] = str(best["session_id"]); mapped.append(out)
    mapped_df = pd.DataFrame(mapped); mapped_sessions = set(mapped_df["session_id"].astype(str)) if not mapped_df.empty else set()
    session_count = int(len(original))
    report = {
        "session_count": session_count, "mapped_session_count": int(len(mapped_sessions)),
        "session_mapping_coverage": float(len(mapped_sessions) / session_count) if session_count else 0.0,
        "conn_count": int(len(conn)), "mapped_conn_count": int(len(mapped_df)),
        "conn_mapping_coverage": float(len(mapped_df) / len(conn)) if len(conn) else 0.0,
        "unmapped_conn_count": int(unmapped),
        "mapping_policy": "expected-wire-hop+execution-time-window",
        "mapping_time_source": time_source,
        "session_to_many_flows": True,
        "expanded_wire_hop_rows": int(len(s)),
    }
    return mapped_df, report


def aggregate_flow_features(sessions: pd.DataFrame, mapped_conn: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []; grouped = {str(k): v for k, v in mapped_conn.groupby("session_id", sort=False)} if not mapped_conn.empty else {}
    for session in sessions.to_dict("records"):
        sid = str(session["session_id"]); frame = grouped.get(sid)
        if frame is None or frame.empty: continue
        duration = pd.to_numeric(frame.get("duration", pd.Series(dtype=float)), errors="coerce").fillna(0.0); ob = pd.to_numeric(frame.get("orig_bytes", pd.Series(dtype=float)), errors="coerce").fillna(0.0); rb = pd.to_numeric(frame.get("resp_bytes", pd.Series(dtype=float)), errors="coerce").fillna(0.0); op = pd.to_numeric(frame.get("orig_pkts", pd.Series(dtype=float)), errors="coerce").fillna(0.0); rp = pd.to_numeric(frame.get("resp_pkts", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        src_b, dst_b, src_p, dst_p = float(ob.sum()), float(rb.sum()), float(op.sum()), float(rp.sum()); services = [str(v) for v in frame.get("service", pd.Series(dtype=object)).dropna().tolist() if str(v) not in {"", "-"}]; app = Counter(services).most_common(1)[0][0] if services else str(session.get("protocol", "unknown"))
        rows.append({"session_id": sid, "flow_count": int(len(frame)), "duration": float(duration.sum()), "src_bytes": src_b, "dst_bytes": dst_b, "src_packets": src_p, "dst_packets": dst_p, "bytes_total": src_b + dst_b, "packets_total": src_p + dst_p, "bytes_ratio": src_b / (dst_b + 1.0), "packets_ratio": src_p / (dst_p + 1.0), "app_proto": app, "dst_port": int(session["dst_port"])})
    return pd.DataFrame(rows)


def _entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0: return 0.0
    return float(-sum((n / total) * math.log2(n / total) for n in counter.values() if n))


def build_temporal_features(sessions: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    required = {"session_id", "src_host_id", "dst_host_id", "src_ip", "dst_ip", "protocol", "start_ts"}; missing = required - set(sessions.columns)
    if missing: raise ValueError(f"sessions missing temporal columns: {sorted(missing)}")
    ordered = sessions.copy(); ordered["_ts"] = _epoch(ordered["start_ts"]); ordered = ordered.sort_values(["_ts", "session_id"]).reset_index(drop=True)
    # (ts, dst_host_id, dst_ip, protocol), retained for 30 simulated days.
    source_history: dict[str, deque[tuple[float, str, str, str]]] = defaultdict(deque)
    pair_seen_all: Counter[tuple[str, str]] = Counter(); dst_seen_all: dict[str, set[str]] = defaultdict(set)
    graph: deque[tuple[float, str, str, bool]] = deque(); out_hour: dict[str, Counter[str]] = defaultdict(Counter); in_hour: dict[str, Counter[str]] = defaultdict(Counter); new_edges_hour: Counter[str] = Counter(); ever_edges: set[tuple[str, str]] = set()
    windows_out: list[dict[str, Any]] = []; graph_out: list[dict[str, Any]] = []
    for row in ordered.to_dict("records"):
        ts = float(row["_ts"]); src = str(row["src_host_id"]); dst = str(row["dst_host_id"]); dst_ip = str(row["dst_ip"]); proto = str(row["protocol"]); sid = str(row["session_id"]); hist = source_history[src]
        while hist and hist[0][0] < ts - WINDOWS["30d"]: hist.popleft()
        history = list(hist)
        def recent(seconds: int): return [e for e in history if e[0] >= ts - seconds]
        h60, h300, h900, h1h = recent(WINDOWS["1m"]), recent(WINDOWS["5m"]), recent(WINDOWS["15m"]), recent(WINDOWS["1h"])
        h24, h7, h30 = recent(WINDOWS["24h"]), recent(WINDOWS["7d"]), history
        pair = (src, dst)
        def pair_count(events): return sum(1 for e in events if e[1] == dst)
        windows_out.append({
            "session_id": sid,
            "connections_1m": len(h60), "connections_5m": len(h300), "connections_15m": len(h900), "connections_1h": len(h1h),
            "connections_24h": len(h24), "connections_7d": len(h7), "connections_30d": len(h30),
            "unique_dst_ip_5m": len({e[2] for e in h300}), "unique_dst_ip_15m": len({e[2] for e in h900}),
            "unique_dst_ip_24h": len({e[2] for e in h24}), "unique_dst_ip_7d": len({e[2] for e in h7}), "unique_dst_ip_30d": len({e[2] for e in h30}),
            "unique_protocols_1h": len({e[3] for e in h1h}),
            "new_dst_for_src": int(dst not in dst_seen_all[src]), "new_src_dst_pair": int(pair_seen_all[pair] == 0),
            "new_dst_24h": int(pair_count(h24) == 0), "new_dst_7d": int(pair_count(h7) == 0), "new_dst_30d": int(pair_count(h30) == 0),
            "pair_seen_count": int(pair_seen_all[pair]), "pair_connections_24h": pair_count(h24), "pair_connections_7d": pair_count(h7), "pair_connections_30d": pair_count(h30),
        })
        while graph and graph[0][0] < ts - WINDOWS["1h"]:
            _, osrc, odst, was_new = graph.popleft(); out_hour[osrc][odst] -= 1; in_hour[odst][osrc] -= 1
            if out_hour[osrc][odst] <= 0: del out_hour[osrc][odst]
            if in_hour[odst][osrc] <= 0: del in_hour[odst][osrc]
            if was_new: new_edges_hour[osrc] -= 1
        graph_out.append({"session_id": sid, "src_out_degree_1h": len(out_hour[src]), "dst_in_degree_1h": len(in_hour[dst]), "new_edge_count_1h": int(new_edges_hour[src]), "protocol_entropy_1h": _entropy(Counter(e[3] for e in h1h)), "protocol_entropy_24h": _entropy(Counter(e[3] for e in h24))})
        was_new = pair not in ever_edges; hist.append((ts, dst, dst_ip, proto)); pair_seen_all[pair] += 1; dst_seen_all[src].add(dst); ever_edges.add(pair); graph.append((ts, src, dst, was_new)); out_hour[src][dst] += 1; in_hour[dst][src] += 1
        if was_new: new_edges_hour[src] += 1
    return pd.DataFrame(windows_out), pd.DataFrame(graph_out)


def select_model_columns(frame: pd.DataFrame, feature_contract: dict[str, Any]) -> pd.DataFrame:
    allowlist = list(map(str, feature_contract.get("production_allowlist", []))); available = [c for c in allowlist if c in frame.columns]
    if not available: raise ValueError("no production features from allowlist are available")
    return frame[available].copy()