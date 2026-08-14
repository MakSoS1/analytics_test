from __future__ import annotations

import bisect
import json
import math
import subprocess
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


def read_zstd_json_lines(path: Path | str) -> pd.DataFrame:
    target = Path(path)
    proc = subprocess.run(
        ["zstd", "-q", "-dc", str(target)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return pd.DataFrame(rows)


def _epoch(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True).astype("int64") / 1_000_000_000.0


def _conn_key(row: pd.Series | dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(row.get("id.orig_h", "")),
        str(row.get("id.resp_h", "")),
        int(row.get("id.resp_p", 0) or 0),
    )


def map_zeek_flows_to_sessions(
    sessions: pd.DataFrame,
    conn: pd.DataFrame,
    *,
    tolerance_seconds: float = 2.0,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    required_sessions = {"session_id", "src_ip", "dst_ip", "dst_port", "start_ts", "end_ts"}
    missing = required_sessions - set(sessions.columns)
    if missing:
        raise ValueError(f"sessions missing required columns: {sorted(missing)}")
    required_conn = {"ts", "id.orig_h", "id.resp_h", "id.resp_p"}
    missing_conn = required_conn - set(conn.columns)
    if missing_conn:
        raise ValueError(f"conn log missing required columns: {sorted(missing_conn)}")

    s = sessions.copy().reset_index(drop=True)
    s["_start"] = _epoch(s["start_ts"])
    s["_end"] = _epoch(s["end_ts"])
    groups: dict[tuple[str, str, int], tuple[list[float], list[dict[str, Any]]]] = {}
    for key, frame in s.groupby(["src_ip", "dst_ip", "dst_port"], sort=False):
        ordered = frame.sort_values("_start")
        groups[(str(key[0]), str(key[1]), int(key[2]))] = (
            ordered["_start"].astype(float).tolist(),
            ordered.to_dict("records"),
        )

    mapped: list[dict[str, Any]] = []
    unmapped = 0
    for row in conn.to_dict("records"):
        key = _conn_key(row)
        group = groups.get(key)
        if group is None:
            unmapped += 1
            continue
        ts = float(row.get("ts", 0.0) or 0.0)
        starts, records = group
        pos = bisect.bisect_right(starts, ts + tolerance_seconds) - 1
        best: dict[str, Any] | None = None
        best_distance = float("inf")
        # A real remote-admin session can emit several TCP flows, but the
        # orchestrator executes sessions serially in a shard. Search a bounded
        # number of recent intervals for the closest containing session.
        for idx in range(pos, max(-1, pos - 16), -1):
            if idx < 0:
                break
            candidate = records[idx]
            if float(candidate["_end"]) + tolerance_seconds < ts:
                break
            if float(candidate["_start"]) - tolerance_seconds <= ts <= float(candidate["_end"]) + tolerance_seconds:
                midpoint = (float(candidate["_start"]) + float(candidate["_end"])) / 2.0
                distance = abs(ts - midpoint)
                if distance < best_distance:
                    best = candidate
                    best_distance = distance
        if best is None:
            unmapped += 1
            continue
        out = dict(row)
        out["session_id"] = str(best["session_id"])
        mapped.append(out)

    mapped_df = pd.DataFrame(mapped)
    mapped_sessions = set(mapped_df["session_id"].astype(str)) if not mapped_df.empty else set()
    report = {
        "session_count": int(len(s)),
        "mapped_session_count": int(len(mapped_sessions)),
        "session_mapping_coverage": float(len(mapped_sessions) / len(s)) if len(s) else 0.0,
        "conn_count": int(len(conn)),
        "mapped_conn_count": int(len(mapped_df)),
        "conn_mapping_coverage": float(len(mapped_df) / len(conn)) if len(conn) else 0.0,
        "unmapped_conn_count": int(unmapped),
        "mapping_policy": "src_ip+dst_ip+dst_port+real-session-time-window",
        "session_to_many_flows": True,
    }
    return mapped_df, report


def aggregate_flow_features(sessions: pd.DataFrame, mapped_conn: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    grouped = {str(k): v for k, v in mapped_conn.groupby("session_id", sort=False)} if not mapped_conn.empty else {}
    for session in sessions.to_dict("records"):
        sid = str(session["session_id"])
        frame = grouped.get(sid)
        if frame is None or frame.empty:
            continue
        duration = pd.to_numeric(frame.get("duration", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        src_bytes = pd.to_numeric(frame.get("orig_bytes", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        dst_bytes = pd.to_numeric(frame.get("resp_bytes", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        src_packets = pd.to_numeric(frame.get("orig_pkts", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        dst_packets = pd.to_numeric(frame.get("resp_pkts", pd.Series(dtype=float)), errors="coerce").fillna(0.0)
        src_b = float(src_bytes.sum())
        dst_b = float(dst_bytes.sum())
        src_p = float(src_packets.sum())
        dst_p = float(dst_packets.sum())
        services = [str(v) for v in frame.get("service", pd.Series(dtype=object)).dropna().tolist() if str(v) not in {"", "-"}]
        app_proto = Counter(services).most_common(1)[0][0] if services else str(session.get("protocol", "unknown"))
        rows.append(
            {
                "session_id": sid,
                "flow_count": int(len(frame)),
                "duration": float(duration.sum()),
                "src_bytes": src_b,
                "dst_bytes": dst_b,
                "src_packets": src_p,
                "dst_packets": dst_p,
                "bytes_total": src_b + dst_b,
                "packets_total": src_p + dst_p,
                "bytes_ratio": float(src_b / (dst_b + 1.0)),
                "packets_ratio": float(src_p / (dst_p + 1.0)),
                "app_proto": app_proto,
                "dst_port": int(session["dst_port"]),
            }
        )
    return pd.DataFrame(rows)


def _entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    value = 0.0
    for count in counter.values():
        p = count / total
        value -= p * math.log2(p)
    return float(value)


def build_temporal_features(sessions: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    required = {"session_id", "src_host_id", "dst_host_id", "src_ip", "dst_ip", "protocol", "start_ts"}
    missing = required - set(sessions.columns)
    if missing:
        raise ValueError(f"sessions missing temporal columns: {sorted(missing)}")
    ordered = sessions.copy()
    ordered["_ts"] = _epoch(ordered["start_ts"])
    ordered = ordered.sort_values(["_ts", "session_id"]).reset_index(drop=True)

    source_history: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
    pair_seen: Counter[tuple[str, str]] = Counter()
    dst_seen_by_src: dict[str, set[str]] = defaultdict(set)
    global_graph: deque[tuple[float, str, str, bool]] = deque()
    src_dst_hour: dict[str, Counter[str]] = defaultdict(Counter)
    dst_src_hour: dict[str, Counter[str]] = defaultdict(Counter)
    new_edges_hour: Counter[str] = Counter()
    ever_edges: set[tuple[str, str]] = set()

    window_rows: list[dict[str, Any]] = []
    graph_rows: list[dict[str, Any]] = []

    for row in ordered.to_dict("records"):
        ts = float(row["_ts"])
        src = str(row["src_host_id"])
        dst = str(row["dst_host_id"])
        dst_ip = str(row["dst_ip"])
        protocol = str(row["protocol"])
        sid = str(row["session_id"])

        hist = source_history[src]
        while hist and hist[0][0] < ts - 3600:
            hist.popleft()
        history = list(hist)

        def recent(seconds: int) -> list[tuple[float, str, str]]:
            threshold = ts - seconds
            return [event for event in history if event[0] >= threshold]

        h60 = recent(60)
        h300 = recent(300)
        h900 = recent(900)
        h3600 = history
        pair = (src, dst)
        new_dst = dst not in dst_seen_by_src[src]
        new_pair = pair_seen[pair] == 0

        window_rows.append(
            {
                "session_id": sid,
                "connections_1m": len(h60),
                "connections_5m": len(h300),
                "connections_15m": len(h900),
                "connections_1h": len(h3600),
                "unique_dst_ip_5m": len({event[1] for event in h300}),
                "unique_dst_ip_15m": len({event[1] for event in h900}),
                "unique_protocols_1h": len({event[2] for event in h3600}),
                "new_dst_for_src": int(new_dst),
                "new_src_dst_pair": int(new_pair),
                "pair_seen_count": int(pair_seen[pair]),
            }
        )

        while global_graph and global_graph[0][0] < ts - 3600:
            _, old_src, old_dst, was_new = global_graph.popleft()
            src_dst_hour[old_src][old_dst] -= 1
            if src_dst_hour[old_src][old_dst] <= 0:
                del src_dst_hour[old_src][old_dst]
            dst_src_hour[old_dst][old_src] -= 1
            if dst_src_hour[old_dst][old_src] <= 0:
                del dst_src_hour[old_dst][old_src]
            if was_new:
                new_edges_hour[old_src] -= 1

        proto_counter = Counter(event[2] for event in h3600)
        graph_rows.append(
            {
                "session_id": sid,
                "src_out_degree_1h": len(src_dst_hour[src]),
                "dst_in_degree_1h": len(dst_src_hour[dst]),
                "new_edge_count_1h": int(new_edges_hour[src]),
                "protocol_entropy_1h": _entropy(proto_counter),
            }
        )

        was_new_edge = pair not in ever_edges
        hist.append((ts, dst_ip, protocol))
        pair_seen[pair] += 1
        dst_seen_by_src[src].add(dst)
        ever_edges.add(pair)
        global_graph.append((ts, src, dst, was_new_edge))
        src_dst_hour[src][dst] += 1
        dst_src_hour[dst][src] += 1
        if was_new_edge:
            new_edges_hour[src] += 1

    return pd.DataFrame(window_rows), pd.DataFrame(graph_rows)


def select_model_columns(frame: pd.DataFrame, feature_contract: dict[str, Any]) -> pd.DataFrame:
    allowlist = list(map(str, feature_contract.get("production_allowlist", [])))
    available = [column for column in allowlist if column in frame.columns]
    if not available:
        raise ValueError("no production features from allowlist are available")
    return frame[available].copy()
