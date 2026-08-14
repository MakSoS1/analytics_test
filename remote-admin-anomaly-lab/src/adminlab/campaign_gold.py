from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone

import pandas as pd


def _ts(value: object) -> float:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _entropy(values: list[str]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if not total:
        return 0.0
    return float(-sum((n / total) * math.log2(n / total) for n in counts.values()))


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    series = pd.Series(values, dtype=float)
    mean = float(series.mean())
    return 0.0 if mean == 0.0 else float(series.std(ddof=0) / mean)


def _numeric_column(group: pd.DataFrame, name: str, default: float = 0.0) -> pd.Series:
    if name in group.columns:
        return pd.to_numeric(group[name], errors="coerce").fillna(default)
    return pd.Series([default] * len(group), index=group.index, dtype=float)


def build_campaign_gold(
    session_features: pd.DataFrame,
    session_labels: pd.DataFrame,
    *,
    environment_id: str = "linux_v2",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if "session_id" not in session_features.columns:
        raise ValueError("session features require session_id")
    required = {"session_id", "campaign_id", "label_binary", "split", "protocol", "src_host_id", "dst_host_id", "start_ts"}
    missing = required - set(session_labels.columns)
    if missing:
        raise ValueError(f"session labels missing {sorted(missing)}")

    joined = session_features.merge(session_labels, on="session_id", how="inner", validate="one_to_one")
    if len(joined) != len(session_features):
        raise ValueError("session feature/label alignment incomplete")

    feature_rows: list[dict[str, object]] = []
    label_rows: list[dict[str, object]] = []
    for campaign_id, group in joined.groupby("campaign_id", sort=False):
        group = group.copy()
        group["_ts"] = group["start_ts"].map(_ts)
        group = group.sort_values(["_ts", "session_id"]).reset_index(drop=True)
        protocols = group["protocol"].astype(str).tolist()
        targets = group["dst_host_id"].astype(str).tolist()
        sources = group["src_host_id"].astype(str).tolist()
        timestamps = group["_ts"].astype(float).tolist()
        gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        transitions = sum(1 for i in range(1, len(protocols)) if protocols[i] != protocols[i - 1])
        target_count = len(set(targets))
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        target_progress = [len(set(targets[: i + 1])) for i in range(len(targets))]
        fanout_slope = 0.0
        if len(target_progress) > 1:
            fanout_slope = float((target_progress[-1] - target_progress[0]) / max(1, len(target_progress) - 1))

        new_target = _numeric_column(group, "new_dst_prior")
        new_protocol = _numeric_column(group, "new_protocol_prior")
        prior_sessions = _numeric_column(group, "prior_sessions_1h")
        pair_seen = _numeric_column(group, "pair_seen_count_prior")
        bytes_total = _numeric_column(group, "session_total_bytes")
        packets_total = _numeric_column(group, "session_total_packets")

        feature_rows.append(
            {
                "campaign_id": str(campaign_id),
                "session_count": int(len(group)),
                "target_count": int(target_count),
                "source_count": int(len(set(sources))),
                "protocol_count": int(len(set(protocols))),
                "new_target_ratio": float(new_target.mean()) if len(group) else 0.0,
                "new_protocol_ratio": float(new_protocol.mean()) if len(group) else 0.0,
                "protocol_transition_count": int(transitions),
                "protocol_entropy": _entropy(protocols),
                "fanout_slope": fanout_slope,
                "campaign_duration_s": float(duration),
                "inter_session_mean_s": float(pd.Series(gaps).mean()) if gaps else 0.0,
                "inter_session_cv": _cv(gaps),
                "unseen_pair_fraction": float((pair_seen == 0).mean()) if len(group) else 0.0,
                "prior_source_sessions_1h_mean": float(prior_sessions.mean()) if len(group) else 0.0,
                "session_total_bytes_sum": float(bytes_total.sum()),
                "session_total_packets_sum": float(packets_total.sum()),
                "session_total_bytes_mean": float(bytes_total.mean()) if len(group) else 0.0,
                "session_total_packets_mean": float(packets_total.mean()) if len(group) else 0.0,
            }
        )

        labels = set(pd.to_numeric(group["label_binary"], errors="raise").astype(int).tolist())
        if len(labels) != 1:
            raise ValueError(f"campaign {campaign_id} mixes labels: {sorted(labels)}")
        splits = set(group["split"].astype(str))
        if len(splits) != 1:
            raise ValueError(f"campaign {campaign_id} crosses splits: {sorted(splits)}")
        label_row: dict[str, object] = {
            "campaign_id": str(campaign_id),
            "label_binary": next(iter(labels)),
            "split": next(iter(splits)),
            "environment_id": environment_id,
            "start_ts": group.iloc[0]["start_ts"],
            "end_ts": group.iloc[-1].get("end_ts", group.iloc[-1]["start_ts"]),
        }
        for field in ("challenge_reason", "campaign_type", "label_family", "sequence_profile"):
            if field in group.columns:
                vals = group[field].dropna().astype(str).unique().tolist()
                label_row[field] = vals[0] if len(vals) == 1 else "mixed"
        label_rows.append(label_row)

    return pd.DataFrame(feature_rows), pd.DataFrame(label_rows)
