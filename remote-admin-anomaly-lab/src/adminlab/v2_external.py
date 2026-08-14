from __future__ import annotations

import math
from collections import Counter, defaultdict

import pandas as pd


WINDOWS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600, "24h": 86400}
REMOTE_ADMIN_PROTOCOLS = {
    22: "ssh",
    135: "dcom",
    445: "smb",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
}


def _entropy(values: list[str]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if not total:
        return 0.0
    return float(-sum((n / total) * math.log2(n / total) for n in counts.values()))


def _protocol(row: pd.Series) -> str:
    dst = int(row["dst_port"]) if pd.notna(row["dst_port"]) else -1
    src = int(row["src_port"]) if pd.notna(row["src_port"]) else -1
    return REMOTE_ADMIN_PROTOCOLS.get(dst) or REMOTE_ADMIN_PROTOCOLS.get(src) or "other"


def build_lanl_session_features(netflow: pd.DataFrame) -> pd.DataFrame:
    """Build V2 session-like features from independent LANL network flows.

    Each retained LANL remote-admin flow is one reference session. Device names
    are used only as ephemeral causal-history keys and are never emitted. LANL
    does not provide V2 class labels, so the returned frame is features only.
    """
    required = {
        "time", "duration", "src_device", "dst_device", "src_port", "dst_port",
        "src_packets", "dst_packets", "src_bytes", "dst_bytes",
    }
    missing = required - set(netflow.columns)
    if missing:
        raise ValueError(f"LANL reference missing columns: {sorted(missing)}")
    if netflow.empty:
        return pd.DataFrame()

    frame = netflow.copy()
    frame["_order"] = range(len(frame))
    frame["time"] = pd.to_numeric(frame["time"], errors="coerce")
    frame = frame.dropna(subset=["time"]).sort_values(["time", "_order"], kind="stable")

    source_history: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
    seen_dsts: dict[str, set[str]] = defaultdict(set)
    seen_protocols: dict[str, set[str]] = defaultdict(set)
    pair_seen: Counter[tuple[str, str]] = Counter()
    pair_last: dict[tuple[str, str], float] = {}
    rows: list[dict[str, float]] = []

    for _, raw in frame.iterrows():
        ts = float(raw["time"])
        src = str(raw["src_device"])
        dst = str(raw["dst_device"])
        protocol = _protocol(raw)
        history = source_history[src]

        def recent(seconds: int) -> list[tuple[float, str, str]]:
            return [event for event in history if 0.0 <= ts - event[0] <= seconds]

        h1m = recent(WINDOWS["1m"])
        h5m = recent(WINDOWS["5m"])
        h15m = recent(WINDOWS["15m"])
        h1h = recent(WINDOWS["1h"])
        h24h = recent(WINDOWS["24h"])
        pair = (src, dst)
        recency = ts - pair_last[pair] if pair in pair_last else -1.0

        src_packets = float(pd.to_numeric(pd.Series([raw["src_packets"]]), errors="coerce").fillna(0).iloc[0])
        dst_packets = float(pd.to_numeric(pd.Series([raw["dst_packets"]]), errors="coerce").fillna(0).iloc[0])
        src_bytes = float(pd.to_numeric(pd.Series([raw["src_bytes"]]), errors="coerce").fillna(0).iloc[0])
        dst_bytes = float(pd.to_numeric(pd.Series([raw["dst_bytes"]]), errors="coerce").fillna(0).iloc[0])
        duration = max(0.0, float(pd.to_numeric(pd.Series([raw["duration"]]), errors="coerce").fillna(0).iloc[0]))
        total_bytes = src_bytes + dst_bytes
        total_packets = src_packets + dst_packets
        seconds = ts % 86400.0
        angle = 2.0 * math.pi * seconds / 86400.0

        rows.append(
            {
                "flow_count": 1.0,
                "session_duration_s": duration,
                "session_total_bytes": total_bytes,
                "session_total_packets": total_packets,
                "session_src_bytes": src_bytes,
                "session_dst_bytes": dst_bytes,
                "flow_duration_mean": duration,
                "flow_duration_max": duration,
                "flow_bytes_mean": total_bytes,
                "flow_bytes_max": total_bytes,
                "prior_sessions_1m": float(len(h1m)),
                "prior_sessions_5m": float(len(h5m)),
                "prior_sessions_15m": float(len(h15m)),
                "prior_sessions_1h": float(len(h1h)),
                "prior_sessions_24h": float(len(h24h)),
                "prior_unique_dst_1h": float(len({event[1] for event in h1h})),
                "prior_unique_dst_24h": float(len({event[1] for event in h24h})),
                "pair_seen_count_prior": float(pair_seen[pair]),
                "pair_recency_s": float(recency),
                "protocol_seen_prior": float(protocol in seen_protocols[src]),
                "source_protocol_diversity_prior": float(len(seen_protocols[src])),
                "new_dst_prior": float(dst not in seen_dsts[src]),
                "new_protocol_prior": float(protocol not in seen_protocols[src]),
                "prior_out_degree_1h": float(len({event[1] for event in h1h})),
                "prior_new_edge_count_1h": float(sum(1 for event in h1h if event[1] != dst)),
                "prior_protocol_entropy_1h": _entropy([event[2] for event in h1h]),
                "prior_protocol_entropy_24h": _entropy([event[2] for event in h24h]),
                "hour_sin": math.sin(angle),
                "hour_cos": math.cos(angle),
                # LANL timestamps are relative to the dataset collection start;
                # day-of-week is intentionally not inferred from an assumed date.
                "is_weekend": 0.0,
            }
        )

        history.append((ts, dst, protocol))
        seen_dsts[src].add(dst)
        seen_protocols[src].add(protocol)
        pair_seen[pair] += 1
        pair_last[pair] = ts

    return pd.DataFrame(rows).reset_index(drop=True)


def align_external_features(
    frame: pd.DataFrame, expected_columns: list[str] | tuple[str, ...]
) -> tuple[pd.DataFrame, dict]:
    expected = [str(name) for name in expected_columns]
    if not expected:
        raise ValueError("expected feature list is empty")
    derived = [name for name in expected if name in frame.columns]
    missing = [name for name in expected if name not in frame.columns]
    aligned = pd.DataFrame(index=frame.index)
    for name in expected:
        if name in frame.columns:
            aligned[name] = pd.to_numeric(frame[name], errors="coerce").fillna(0.0).astype(float)
        else:
            aligned[name] = 0.0
    report = {
        "expected_feature_count": len(expected),
        "derived_feature_count": len(derived),
        "imputed_feature_count": len(missing),
        "coverage_fraction": len(derived) / len(expected),
        "derived_features": derived,
        "imputed_features": missing,
        "imputation_value": 0.0,
        "identity_columns_emitted": False,
    }
    return aligned, report
