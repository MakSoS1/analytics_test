from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pandas as pd


WINDOWS = {
    "1m": 60,
    "5m": 300,
    "15m": 900,
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}


def _ts(value: object) -> float:
    text = str(value)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _entropy(values: list[str]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if not total:
        return 0.0
    return float(-sum((n / total) * math.log2(n / total) for n in counts.values()))


def _numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(0.0)


def _assert_consistent(group: pd.DataFrame, field: str, session_id: str) -> object:
    if field not in group.columns:
        return ""
    vals = group[field].dropna().astype(str).unique().tolist()
    if len(vals) > 1:
        raise ValueError(f"session {session_id} has inconsistent {field}: {vals}")
    return vals[0] if vals else ""


def _protocol_switch_count(events: list[tuple[float, str, str, int]]) -> int:
    if len(events) < 2:
        return 0
    ordered = sorted(events, key=lambda event: event[0])
    return sum(1 for left, right in zip(ordered, ordered[1:]) if left[2] != right[2])


def build_session_gold(
    flow_features: pd.DataFrame,
    flow_labels: pd.DataFrame,
    *,
    environment_id: str = "linux_v2",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Aggregate parser-observed flow Gold into causal session Gold.

    Host identifiers from the label side are used only as ephemeral state keys,
    equivalent to production src/dst IP keys. They are never emitted as model
    features. Evaluation-only task/persona/fidelity metadata stays exclusively
    in the label table so hard-negative and slice audits remain reproducible.

    V3 extends the same single chronological pass with 7d/30d graph/history
    features. Every emitted value is computed before the current session is
    added to state, so future rows cannot alter earlier session features.
    """
    required_features = {"flow_uid", "session_id"}
    required_labels = {
        "flow_uid", "session_id", "label_binary", "split", "campaign_id",
        "protocol", "src_host_id", "dst_host_id", "start_ts", "end_ts",
    }
    missing = required_features - set(flow_features.columns)
    if missing:
        raise ValueError(f"flow features missing {sorted(missing)}")
    missing = required_labels - set(flow_labels.columns)
    if missing:
        raise ValueError(f"flow labels missing {sorted(missing)}")

    joined = flow_features.merge(
        flow_labels,
        on=["flow_uid", "session_id"],
        how="inner",
        validate="one_to_one",
        suffixes=("", "_label"),
    )
    if len(joined) != len(flow_features):
        raise ValueError("flow feature/label alignment incomplete")

    session_groups: dict[str, pd.DataFrame] = {
        str(sid): grp.copy() for sid, grp in joined.groupby("session_id", sort=False)
    }
    order: list[tuple[float, str]] = []
    for sid, grp in session_groups.items():
        order.append((_ts(_assert_consistent(grp, "start_ts", sid)), sid))
    order.sort(key=lambda item: (item[0], item[1]))

    source_history: dict[str, list[tuple[float, str, str, int]]] = defaultdict(list)
    pair_seen: Counter[tuple[str, str]] = Counter()
    pair_last_ts: dict[tuple[str, str], float] = {}
    source_protocols: dict[str, set[str]] = defaultdict(set)
    source_destinations: dict[str, set[str]] = defaultdict(set)

    feature_rows: list[dict[str, object]] = []
    label_rows: list[dict[str, object]] = []

    for start, sid in order:
        grp = session_groups[sid]
        src = str(_assert_consistent(grp, "src_host_id", sid))
        dst = str(_assert_consistent(grp, "dst_host_id", sid))
        protocol = str(_assert_consistent(grp, "protocol", sid))
        end = _ts(_assert_consistent(grp, "end_ts", sid))

        history = source_history[src]

        def recent(seconds: int) -> list[tuple[float, str, str, int]]:
            return [event for event in history if start - seconds <= event[0] < start]

        h1m = recent(WINDOWS["1m"])
        h5m = recent(WINDOWS["5m"])
        h15m = recent(WINDOWS["15m"])
        h1h = recent(WINDOWS["1h"])
        h24h = recent(WINDOWS["24h"])
        h7d = recent(WINDOWS["7d"])
        h30d = recent(WINDOWS["30d"])
        pair = (src, dst)
        recency = start - pair_last_ts[pair] if pair in pair_last_ts else -1.0
        new_destination = int(dst not in source_destinations[src])
        new_protocol = int(protocol not in source_protocols[src])
        new_targets_24h = sum(int(event[3]) for event in h24h)

        bytes_total = _numeric(grp.get("bytes_total", pd.Series([0] * len(grp), index=grp.index)))
        packets_total = _numeric(grp.get("packets_total", pd.Series([0] * len(grp), index=grp.index)))
        durations = _numeric(grp.get("duration", pd.Series([0] * len(grp), index=grp.index)))
        src_bytes = _numeric(grp.get("src_bytes", pd.Series([0] * len(grp), index=grp.index)))
        dst_bytes = _numeric(grp.get("dst_bytes", pd.Series([0] * len(grp), index=grp.index)))

        dt = datetime.fromtimestamp(start, tz=timezone.utc)
        seconds = dt.hour * 3600 + dt.minute * 60 + dt.second
        angle = 2.0 * math.pi * seconds / 86400.0

        row: dict[str, object] = {
            "session_id": sid,
            "flow_count": int(len(grp)),
            "session_duration_s": max(0.0, end - start),
            "session_total_bytes": float(bytes_total.sum()),
            "session_total_packets": float(packets_total.sum()),
            "session_src_bytes": float(src_bytes.sum()),
            "session_dst_bytes": float(dst_bytes.sum()),
            "flow_duration_mean": float(durations.mean()) if len(durations) else 0.0,
            "flow_duration_max": float(durations.max()) if len(durations) else 0.0,
            "flow_bytes_mean": float(bytes_total.mean()) if len(bytes_total) else 0.0,
            "flow_bytes_max": float(bytes_total.max()) if len(bytes_total) else 0.0,
            "prior_sessions_1m": len(h1m),
            "prior_sessions_5m": len(h5m),
            "prior_sessions_15m": len(h15m),
            "prior_sessions_1h": len(h1h),
            "prior_sessions_24h": len(h24h),
            "prior_unique_dst_1h": len({event[1] for event in h1h}),
            "prior_unique_dst_24h": len({event[1] for event in h24h}),
            "pair_seen_count_prior": int(pair_seen[pair]),
            "pair_recency_s": float(recency),
            "protocol_seen_prior": int(protocol in source_protocols[src]),
            "source_protocol_diversity_prior": len(source_protocols[src]),
            "new_dst_prior": new_destination,
            "new_protocol_prior": new_protocol,
            "prior_out_degree_1h": len({event[1] for event in h1h}),
            "prior_new_edge_count_1h": sum(int(event[3]) for event in h1h),
            "prior_protocol_entropy_1h": _entropy([event[2] for event in h1h]),
            "prior_protocol_entropy_24h": _entropy([event[2] for event in h24h]),
            "src_distinct_dst_24h_prior": len({event[1] for event in h24h}),
            "src_distinct_dst_7d_prior": len({event[1] for event in h7d}),
            "src_distinct_dst_30d_prior": len({event[1] for event in h30d}),
            "time_since_pair_seen_seconds_prior": float(recency),
            "new_destination_for_source": new_destination,
            "new_protocol_for_source": new_protocol,
            "src_protocol_diversity_7d_prior": len({event[2] for event in h7d}),
            "src_new_target_count_1h_prior": sum(int(event[3]) for event in h1h),
            "src_new_target_count_24h_prior": int(new_targets_24h),
            "src_graph_expansion_rate_24h_prior": float(new_targets_24h / max(1, len(h24h))),
            "recent_protocol_switch_count_prior": int(_protocol_switch_count(h7d)),
            "recent_remote_admin_attempt_count_prior": int(len(h24h)),
            "hour_sin": math.sin(angle),
            "hour_cos": math.cos(angle),
            "is_weekend": int(dt.weekday() >= 5),
        }

        for source_col in (
            "connections_1h", "connections_24h", "unique_dst_ip_24h",
            "pair_seen_count", "protocol_entropy_1h", "new_dst_for_src",
            "new_src_dst_pair",
        ):
            if source_col in grp.columns:
                values = _numeric(grp[source_col])
                row[f"flow_state_{source_col}_max"] = float(values.max()) if len(values) else 0.0
                row[f"flow_state_{source_col}_mean"] = float(values.mean()) if len(values) else 0.0

        feature_rows.append(row)

        label_fields = [
            "campaign_id", "label_binary", "split", "challenge_reason", "protocol",
            "persona_id", "task_id", "calendar_id", "implementation_id",
            "src_host_id", "dst_host_id", "start_ts", "end_ts", "scenario_id", "pair_id",
            "label_family", "campaign_type", "behavior_profile", "intent_profile",
            "historical_relation", "sequence_profile", "simulated_day", "auth_outcome",
            "wire_fidelity", "semantic_fidelity", "client_stack", "server_stack",
        ]
        label_row: dict[str, object] = {"session_id": sid, "environment_id": environment_id}
        for field in label_fields:
            if field in grp.columns:
                value = _assert_consistent(grp, field, sid)
                if field == "label_binary" and value != "":
                    value = int(float(value))
                label_row[field] = value
        label_rows.append(label_row)

        was_new_destination = int(dst not in source_destinations[src])
        history.append((start, dst, protocol, was_new_destination))
        source_destinations[src].add(dst)
        source_protocols[src].add(protocol)
        pair_seen[pair] += 1
        pair_last_ts[pair] = start

    return pd.DataFrame(feature_rows), pd.DataFrame(label_rows)
