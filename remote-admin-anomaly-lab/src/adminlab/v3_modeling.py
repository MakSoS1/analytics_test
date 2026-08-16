from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from .modeling import build_supervised_pipeline

# Session research-view groups retained for backward-compatible diagnostics.
TIME_ONLY = ("hour_sin", "hour_cos", "is_weekend")
CURRENT_SESSION_ONLY = (
    "flow_count", "session_duration_s", "session_total_bytes", "session_total_packets",
    "session_src_bytes", "session_dst_bytes", "flow_duration_mean", "flow_duration_max",
    "flow_bytes_mean", "flow_bytes_max", "hour_sin", "hour_cos", "is_weekend",
)
BYTES_PACKETS_ONLY = (
    "session_total_bytes", "session_total_packets", "session_src_bytes", "session_dst_bytes",
    "flow_bytes_mean", "flow_bytes_max",
)
DURATION_RATE_ONLY = (
    "session_duration_s", "flow_duration_mean", "flow_duration_max", "flow_count",
)
HISTORY_ONLY = (
    "src_distinct_dst_24h_prior", "src_distinct_dst_7d_prior", "src_distinct_dst_30d_prior",
    "pair_seen_count_prior", "time_since_pair_seen_seconds_prior", "new_destination_for_source",
    "new_protocol_for_source", "src_protocol_diversity_7d_prior", "src_new_target_count_1h_prior",
    "src_new_target_count_24h_prior", "src_graph_expansion_rate_24h_prior",
    "recent_protocol_switch_count_prior", "recent_remote_admin_attempt_count_prior",
)

# NGFW production-view groups. These use the same features emitted by
# adminlab.online_features.EveFeatureState and scored by score_eve_sidecar.py.
FLOW_TIME_ONLY = ("hour_sin", "hour_cos", "is_weekend")
FLOW_PROTOCOL_ONLY = ("app_proto", "dst_port")
FLOW_BYTES_PACKETS_ONLY = (
    "src_bytes", "dst_bytes", "src_packets", "dst_packets", "bytes_total", "packets_total",
    "bytes_ratio", "packets_ratio",
)
FLOW_DURATION_ONLY = ("duration",)
FLOW_CURRENT_SESSION_ONLY = (
    "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "bytes_total",
    "packets_total", "bytes_ratio", "packets_ratio", "app_proto", "dst_port",
    "hour_sin", "hour_cos", "is_weekend",
)
FLOW_HISTORY_ONLY = (
    "connections_1m", "connections_5m", "connections_15m", "connections_1h",
    "connections_24h", "connections_7d", "connections_30d",
    "unique_dst_ip_5m", "unique_dst_ip_15m", "unique_dst_ip_24h", "unique_dst_ip_7d",
    "unique_dst_ip_30d", "unique_protocols_1h", "new_dst_for_src", "new_src_dst_pair",
    "new_dst_24h", "new_dst_7d", "new_dst_30d", "pair_seen_count", "pair_recency_s",
    "pair_connections_24h", "pair_connections_7d", "pair_connections_30d",
    "source_protocol_seen_count_prior", "source_protocol_novelty",
    "source_pair_protocol_seen_count_prior", "destination_seen_count_prior",
    "src_out_degree_1h", "dst_in_degree_1h", "new_edge_count_1h", "new_edge_ratio_1h",
    "recent_protocol_switch_count_1h", "protocol_entropy_1h", "protocol_entropy_24h",
)


def _available(frame: pd.DataFrame, columns: tuple[str, ...]) -> list[str]:
    return [column for column in columns if column in frame.columns]


def _lightgbm_baseline(frame: pd.DataFrame, columns: tuple[str, ...], *, seed: int) -> dict[str, Any]:
    """Train the exact same estimator family used by the full V3 model."""
    cols = _available(frame, columns)
    if not cols:
        return {"status": "unavailable", "columns": [], "validation_pr_auc": None, "estimator": "LightGBM"}
    train = frame[frame["split"].astype(str) == "train"].copy()
    val = frame[frame["split"].astype(str) == "validation"].copy()
    if train.empty or val.empty or train["label_binary"].nunique() < 2 or val["label_binary"].nunique() < 2:
        return {
            "status": "unavailable_split", "columns": cols, "validation_pr_auc": None,
            "estimator": "LightGBM",
        }
    x_train = train[cols].copy()
    x_val = val[cols].copy()
    y_train = train["label_binary"].astype(int).to_numpy()
    y_val = val["label_binary"].astype(int).to_numpy()
    pipeline = build_supervised_pipeline(x_train, seed=seed)
    pipeline.fit(x_train, y_train)
    scores = pipeline.predict_proba(x_val)[:, 1]
    return {
        "status": "ok",
        "columns": cols,
        "validation_pr_auc": float(average_precision_score(y_val, scores)),
        "train_rows": int(len(train)),
        "validation_rows": int(len(val)),
        "estimator": "LightGBM",
    }


def _prevalence_pr_auc(frame: pd.DataFrame) -> float:
    val = frame[frame["split"].astype(str) == "validation"]
    if val.empty:
        return 0.0
    y = val["label_binary"].astype(int).to_numpy()
    prevalence = float(np.mean(y))
    return float(average_precision_score(y, np.full(len(y), prevalence, dtype=float)))


def v3_flow_shortcut_audit(
    frame: pd.DataFrame,
    *,
    full_model_pr_auc: float,
    seed: int = 2026081403,
) -> dict[str, Any]:
    required = {"label_binary", "split"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"V3 flow model matrix missing {sorted(missing)}")
    baselines = {
        "time_only": _lightgbm_baseline(frame, FLOW_TIME_ONLY, seed=seed),
        "protocol_only": _lightgbm_baseline(frame, FLOW_PROTOCOL_ONLY, seed=seed),
        "bytes_packets_only": _lightgbm_baseline(frame, FLOW_BYTES_PACKETS_ONLY, seed=seed),
        "duration_only": _lightgbm_baseline(frame, FLOW_DURATION_ONLY, seed=seed),
        "current_session_only": _lightgbm_baseline(frame, FLOW_CURRENT_SESSION_ONLY, seed=seed),
        "history_only": _lightgbm_baseline(frame, FLOW_HISTORY_ONLY, seed=seed),
    }
    nuisance_names = (
        "time_only", "protocol_only", "bytes_packets_only", "duration_only", "current_session_only",
    )
    nuisance_scores = [
        float(baselines[name]["validation_pr_auc"])
        for name in nuisance_names
        if baselines[name].get("validation_pr_auc") is not None
    ]
    best_nuisance = max(nuisance_scores, default=1.0)
    history = baselines["history_only"].get("validation_pr_auc")
    current = baselines["current_session_only"].get("validation_pr_auc")
    prevalence = _prevalence_pr_auc(frame)
    return {
        "schema_version": 4,
        "primary_unit": "suricata_eve_flow",
        "estimator_policy": "same LightGBM pipeline/hyperparameters for full and every ablation",
        "full_model_pr_auc": float(full_model_pr_auc),
        "prevalence_pr_auc": float(prevalence),
        "history_only_pr_auc": float(history) if history is not None else None,
        "current_session_only_pr_auc": float(current) if current is not None else None,
        "best_nuisance_pr_auc": float(best_nuisance),
        "full_over_best_nuisance_margin": float(full_model_pr_auc - best_nuisance),
        "history_over_prevalence_margin": float(history - prevalence) if history is not None else None,
        "baselines": baselines,
        "policy": "flow-primary must beat all nuisance-only views; history-only must materially beat prevalence",
    }


def v3_shortcut_audit(
    frame: pd.DataFrame,
    *,
    full_model_pr_auc: float,
    seed: int = 2026081403,
) -> dict[str, Any]:
    """Session research-view audit, now estimator-identical too."""
    required = {"label_binary", "split"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"V3 model matrix missing {sorted(missing)}")
    baselines = {
        "time_only": _lightgbm_baseline(frame, TIME_ONLY, seed=seed),
        "current_session_only": _lightgbm_baseline(frame, CURRENT_SESSION_ONLY, seed=seed),
        "bytes_packets_only": _lightgbm_baseline(frame, BYTES_PACKETS_ONLY, seed=seed),
        "duration_rate_only": _lightgbm_baseline(frame, DURATION_RATE_ONLY, seed=seed),
        "history_only": _lightgbm_baseline(frame, HISTORY_ONLY, seed=seed),
    }
    nuisance_names = ("time_only", "bytes_packets_only", "duration_rate_only", "current_session_only")
    nuisance_scores = [
        float(baselines[name]["validation_pr_auc"])
        for name in nuisance_names
        if baselines[name].get("validation_pr_auc") is not None
    ]
    best_nuisance = max(nuisance_scores, default=1.0)
    current = baselines["current_session_only"].get("validation_pr_auc")
    time_only = baselines["time_only"].get("validation_pr_auc")
    history = baselines["history_only"].get("validation_pr_auc")
    return {
        "schema_version": 4,
        "primary_unit": "session_research_view",
        "full_model_pr_auc": float(full_model_pr_auc),
        "time_only_pr_auc": float(time_only) if time_only is not None else 1.0,
        "current_session_only_pr_auc": float(current) if current is not None else 1.0,
        "history_only_pr_auc": float(history) if history is not None else None,
        "best_nuisance_pr_auc": float(best_nuisance),
        "full_over_current_session_margin": float(full_model_pr_auc - (float(current) if current is not None else 1.0)),
        "full_over_best_nuisance_margin": float(full_model_pr_auc - best_nuisance),
        "baselines": baselines,
        "estimator_policy": "same LightGBM pipeline/hyperparameters for full and every ablation",
        "policy": "session research model must beat current-session and all nuisance-only views",
    }
