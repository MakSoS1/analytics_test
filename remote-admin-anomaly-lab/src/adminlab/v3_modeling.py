from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score


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


def _available(frame: pd.DataFrame, columns: tuple[str, ...]) -> list[str]:
    return [column for column in columns if column in frame.columns]


def _baseline(frame: pd.DataFrame, columns: tuple[str, ...], *, seed: int) -> dict[str, Any]:
    cols = _available(frame, columns)
    if not cols:
        return {"status": "unavailable", "columns": [], "validation_pr_auc": None}
    train = frame[frame["split"] == "train"].copy()
    val = frame[frame["split"] == "validation"].copy()
    if train.empty or val.empty or train["label_binary"].nunique() < 2 or val["label_binary"].nunique() < 2:
        return {"status": "unavailable_split", "columns": cols, "validation_pr_auc": None}
    x_train = train[cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    x_val = val[cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y_train = train["label_binary"].astype(int)
    y_val = val["label_binary"].astype(int)
    model = HistGradientBoostingClassifier(
        learning_rate=0.05,
        max_iter=120,
        max_leaf_nodes=15,
        min_samples_leaf=12,
        l2_regularization=1.0,
        random_state=seed,
    )
    model.fit(x_train, y_train)
    scores = model.predict_proba(x_val)[:, 1]
    return {
        "status": "ok",
        "columns": cols,
        "validation_pr_auc": float(average_precision_score(y_val, scores)),
        "train_rows": int(len(train)),
        "validation_rows": int(len(val)),
    }


def v3_shortcut_audit(
    frame: pd.DataFrame,
    *,
    full_model_pr_auc: float,
    seed: int = 2026081403,
) -> dict[str, Any]:
    required = {"label_binary", "split"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"V3 model matrix missing {sorted(missing)}")
    baselines = {
        "time_only": _baseline(frame, TIME_ONLY, seed=seed + 1),
        "current_session_only": _baseline(frame, CURRENT_SESSION_ONLY, seed=seed + 2),
        "bytes_packets_only": _baseline(frame, BYTES_PACKETS_ONLY, seed=seed + 3),
        "duration_rate_only": _baseline(frame, DURATION_RATE_ONLY, seed=seed + 4),
        "history_only": _baseline(frame, HISTORY_ONLY, seed=seed + 5),
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
    return {
        "schema_version": 3,
        "full_model_pr_auc": float(full_model_pr_auc),
        "time_only_pr_auc": float(time_only) if time_only is not None else 1.0,
        "current_session_only_pr_auc": float(current) if current is not None else 1.0,
        "best_nuisance_pr_auc": float(best_nuisance),
        "full_over_current_session_margin": float(full_model_pr_auc - (float(current) if current is not None else 1.0)),
        "full_over_best_nuisance_margin": float(full_model_pr_auc - best_nuisance),
        "baselines": baselines,
        "policy": "V3 full session model must beat current-session and all nuisance-only views; history-only is reported as intended-signal ablation",
    }
