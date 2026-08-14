from __future__ import annotations

from typing import Any

import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


FORBIDDEN_FEATURE_COLUMNS = {
    "label_binary",
    "label_family",
    "split",
    "challenge_reason",
    "scenario_id",
    "campaign_id",
    "session_id",
    "flow_uid",
    "pair_id",
    "campaign_type",
    "behavior_profile",
    "intent_profile",
    "historical_relation",
    "sequence_profile",
    "implementation_id",
    "environment_id",
    "generator_seed",
    "netem_profile",
    "src_host_id",
    "dst_host_id",
    "src_ip",
    "dst_ip",
    "persona_id",
    "task_id",
    "calendar_id",
    "wire_fidelity",
    "semantic_fidelity",
    "ground_truth_source",
    "client_stack",
    "server_stack",
}


SESSION_NUISANCE_FAMILIES = {
    "bytes_packets": [
        "session_total_bytes",
        "session_total_packets",
        "session_src_bytes",
        "session_dst_bytes",
        "flow_bytes_mean",
        "flow_bytes_max",
    ],
    "duration_rate": [
        "session_duration_s",
        "flow_duration_mean",
        "flow_duration_max",
        "flow_count",
    ],
    "time_only": ["hour_sin", "hour_cos", "is_weekend"],
    "current_session_only": [
        "flow_count",
        "session_duration_s",
        "session_total_bytes",
        "session_total_packets",
        "session_src_bytes",
        "session_dst_bytes",
        "flow_duration_mean",
        "flow_duration_max",
        "flow_bytes_mean",
        "flow_bytes_max",
        "hour_sin",
        "hour_cos",
        "is_weekend",
    ],
}


def training_mask(labels: pd.DataFrame) -> pd.Series:
    """Return the only rows permitted to fit V2 supervised models."""
    required = {"environment_id", "split"}
    missing = required - set(labels.columns)
    if missing:
        raise ValueError(f"labels missing training boundary columns: {sorted(missing)}")
    return labels["environment_id"].astype(str).eq("linux_v2") & labels["split"].astype(str).eq("train")


def assert_feature_frame_safe(frame: pd.DataFrame) -> None:
    leaked = sorted(FORBIDDEN_FEATURE_COLUMNS & set(map(str, frame.columns)))
    if leaked:
        raise ValueError(f"forbidden V2 model features present: {leaked}")

    bad_objects: list[str] = []
    for column in frame.columns:
        if pd.api.types.is_object_dtype(frame[column]) or pd.api.types.is_string_dtype(frame[column]):
            bad_objects.append(str(column))
    if bad_objects:
        raise ValueError(f"non-numeric V2 model features require explicit encoding: {sorted(bad_objects)}")

    if frame.empty:
        raise ValueError("V2 feature frame is empty")


def _nuisance_baseline(train: pd.DataFrame, validation: pd.DataFrame, columns: list[str]) -> dict[str, Any]:
    columns = [name for name in columns if name in train.columns and name in validation.columns]
    if not columns:
        return {"status": "unavailable", "reason": "features_missing"}
    y_train = train["label_binary"].astype(int).to_numpy()
    y_val = validation["label_binary"].astype(int).to_numpy()
    if len(set(y_train.tolist())) < 2 or len(set(y_val.tolist())) < 2:
        return {"status": "unavailable", "reason": "two_classes_required"}
    pipeline = Pipeline(
        [
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=0)),
        ]
    )
    pipeline.fit(train[columns], y_train)
    score = pipeline.predict_proba(validation[columns])[:, 1]
    return {
        "status": "ok",
        "features": columns,
        "pr_auc": float(average_precision_score(y_val, score)),
        "roc_auc": float(roc_auc_score(y_val, score)),
    }


def session_shortcut_audit(
    model_matrix: pd.DataFrame,
    *,
    full_model_pr_auc: float,
    required_margin: float = 0.05,
) -> dict[str, Any]:
    if not {"label_binary", "split"} <= set(model_matrix.columns):
        raise ValueError("V2 shortcut audit requires label_binary and split")
    train = model_matrix[model_matrix["split"].astype(str) == "train"].copy()
    validation = model_matrix[model_matrix["split"].astype(str) == "validation"].copy()
    if train.empty or validation.empty:
        raise ValueError("V2 shortcut audit requires train and validation")
    baselines = {
        name: _nuisance_baseline(train, validation, columns)
        for name, columns in SESSION_NUISANCE_FAMILIES.items()
    }
    available = {name: result for name, result in baselines.items() if result.get("status") == "ok"}
    if not available:
        return {
            "full_model_pr_auc": float(full_model_pr_auc),
            "required_margin": float(required_margin),
            "baselines": baselines,
            "best_baseline": None,
            "best_baseline_pr_auc": None,
            "shortcut_margin": None,
            "shortcut_risk": True,
            "reason": "no_nuisance_baseline_available",
        }
    best_name, best = max(available.items(), key=lambda item: float(item[1]["pr_auc"]))
    best_pr = float(best["pr_auc"])
    margin = float(full_model_pr_auc) - best_pr
    return {
        "full_model_pr_auc": float(full_model_pr_auc),
        "required_margin": float(required_margin),
        "baselines": baselines,
        "best_baseline": best_name,
        "best_baseline_pr_auc": best_pr,
        "shortcut_margin": margin,
        "shortcut_risk": margin < float(required_margin),
        "policy": "session-primary validation PR-AUC must exceed the best nuisance-only baseline by at least the configured margin",
    }
