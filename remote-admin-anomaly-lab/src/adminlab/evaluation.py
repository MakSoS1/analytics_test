from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def prevalence_precision(*, tpr: float, fpr: float, prevalence: float) -> float:
    if not 0 <= prevalence <= 1:
        raise ValueError("prevalence must be in [0,1]")
    numerator = float(tpr) * prevalence
    denominator = numerator + float(fpr) * (1.0 - prevalence)
    return float(numerator / denominator) if denominator > 0 else 1.0


def _point(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if fp + tn else 0.0
    recall = float(tp / (tp + fn)) if tp + fn else 0.0
    precision = float(tp / (tp + fp)) if tp + fp else 0.0
    return {
        "threshold": float(threshold),
        "recall": recall,
        "precision": precision,
        "fpr": fpr,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "fp_per_10k_benign": float(10000.0 * fpr),
    }


def operating_point_at_fpr(y: np.ndarray, score: np.ndarray, max_fpr: float) -> dict[str, Any]:
    y = np.asarray(y, dtype=int)
    score = np.asarray(score, dtype=float)
    if len(y) != len(score) or not len(y):
        raise ValueError("y and score must be non-empty and aligned")
    if len(np.unique(y)) < 2:
        raise ValueError("operating point requires both classes")
    finite = score[np.isfinite(score)]
    if not len(finite):
        raise ValueError("score has no finite values")
    eps = np.finfo(float).eps * max(1.0, float(np.max(np.abs(finite))))
    candidates = np.unique(np.concatenate(([float(np.max(finite)) + eps], finite, [float(np.min(finite)) - eps])))
    best: dict[str, Any] | None = None
    for threshold in candidates:
        point = _point(y, score, float(threshold))
        if point["fpr"] > max_fpr + 1e-15:
            continue
        if best is None or (point["recall"], point["precision"], -point["threshold"]) > (
            best["recall"], best["precision"], -best["threshold"]
        ):
            best = point
    if best is None:
        best = _point(y, score, float(np.max(finite)) + eps)
    best["max_fpr_constraint"] = float(max_fpr)
    return best


def evaluate_operating_points(
    y: np.ndarray,
    score: np.ndarray,
    *,
    probability_scores: bool = False,
) -> dict[str, Any]:
    y = np.asarray(y, dtype=int)
    score = np.asarray(score, dtype=float)
    if len(np.unique(y)) < 2:
        raise ValueError("evaluation requires both classes")
    report: dict[str, Any] = {
        "n": int(len(y)),
        "positive": int(y.sum()),
        "negative": int((1 - y).sum()),
        "pr_auc": float(average_precision_score(y, score)),
        "roc_auc": float(roc_auc_score(y, score)),
        "operating_points": {
            "fpr_1pct": operating_point_at_fpr(y, score, 0.01),
            "fpr_0_1pct": operating_point_at_fpr(y, score, 0.001),
        },
    }
    if probability_scores:
        report["brier"] = float(brier_score_loss(y, np.clip(score, 0.0, 1.0)))
    # Production precision is prevalence-sensitive. Report stress scenarios using
    # the stricter 0.1% FPR operating point rather than dataset class balance.
    strict = report["operating_points"]["fpr_0_1pct"]
    report["precision_at_prevalence"] = {
        "0.1%": prevalence_precision(tpr=strict["recall"], fpr=strict["fpr"], prevalence=0.001),
        "1%": prevalence_precision(tpr=strict["recall"], fpr=strict["fpr"], prevalence=0.01),
    }
    return report


def campaign_bootstrap_ci(
    frame: pd.DataFrame,
    *,
    campaign_col: str = "campaign_id",
    label_col: str = "label_binary",
    score_col: str = "score",
    n_bootstrap: int = 1000,
    seed: int = 20260814,
) -> dict[str, Any]:
    required = {campaign_col, label_col, score_col}
    if not required <= set(frame.columns):
        raise ValueError(f"bootstrap frame missing {sorted(required - set(frame.columns))}")
    campaigns = sorted(frame[campaign_col].astype(str).unique())
    if len(campaigns) < 2:
        raise ValueError("campaign bootstrap requires at least two campaigns")
    groups = {name: frame[frame[campaign_col].astype(str) == name] for name in campaigns}
    rng = np.random.default_rng(seed)
    ap_values: list[float] = []
    roc_values: list[float] = []
    for _ in range(int(n_bootstrap)):
        sampled = rng.choice(campaigns, size=len(campaigns), replace=True)
        boot = pd.concat([groups[str(name)] for name in sampled], ignore_index=True)
        y = boot[label_col].astype(int).to_numpy()
        if len(np.unique(y)) < 2:
            continue
        score = pd.to_numeric(boot[score_col], errors="coerce").fillna(0.0).to_numpy(dtype=float)
        ap_values.append(float(average_precision_score(y, score)))
        roc_values.append(float(roc_auc_score(y, score)))
    if not ap_values:
        raise ValueError("bootstrap produced no two-class samples")
    return {
        "campaigns": int(len(campaigns)),
        "bootstrap_samples": int(len(ap_values)),
        "pr_auc_ci95": [float(np.quantile(ap_values, 0.025)), float(np.quantile(ap_values, 0.975))],
        "roc_auc_ci95": [float(np.quantile(roc_values, 0.025)), float(np.quantile(roc_values, 0.975))],
    }


def _numeric_baseline(train: pd.DataFrame, val: pd.DataFrame, columns: list[str]) -> dict[str, Any]:
    columns = [c for c in columns if c in train.columns and c in val.columns]
    if not columns:
        return {"status": "unavailable", "reason": "features_missing"}
    y_train = train["label_binary"].astype(int).to_numpy()
    y_val = val["label_binary"].astype(int).to_numpy()
    if len(np.unique(y_train)) < 2 or len(np.unique(y_val)) < 2:
        return {"status": "unavailable", "reason": "two_classes_required"}
    pipeline = Pipeline([
        ("impute", SimpleImputer(strategy="median")),
        ("scale", StandardScaler()),
        ("model", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=0)),
    ])
    pipeline.fit(train[columns], y_train)
    score = pipeline.predict_proba(val[columns])[:, 1]
    return {
        "status": "ok",
        "features": columns,
        "pr_auc": float(average_precision_score(y_val, score)),
        "roc_auc": float(roc_auc_score(y_val, score)),
    }


def _categorical_baseline(train: pd.DataFrame, val: pd.DataFrame, column: str) -> dict[str, Any]:
    if column not in train.columns or column not in val.columns:
        return {"status": "unavailable", "reason": "features_missing"}
    y_val = val["label_binary"].astype(int).to_numpy()
    if len(np.unique(y_val)) < 2:
        return {"status": "unavailable", "reason": "two_classes_required"}
    global_rate = float(train["label_binary"].mean())
    rates = train.groupby(column, dropna=False)["label_binary"].mean().to_dict()
    score = val[column].map(rates).fillna(global_rate).to_numpy(dtype=float)
    return {
        "status": "ok",
        "features": [column],
        "pr_auc": float(average_precision_score(y_val, score)),
        "roc_auc": float(roc_auc_score(y_val, score)),
    }


def shortcut_audit(
    frame: pd.DataFrame,
    *,
    full_model_pr_auc: float,
    tolerance: float = 0.02,
    high_shortcut_auc: float = 0.90,
) -> dict[str, Any]:
    required = {"label_binary", "split"}
    if not required <= set(frame.columns):
        raise ValueError("shortcut audit requires label_binary and split")
    train = frame[frame["split"].astype(str) == "train"].copy()
    val = frame[frame["split"].astype(str) == "validation"].copy()
    if train.empty or val.empty:
        raise ValueError("shortcut audit requires train and validation")
    baselines = {
        "port_only": _numeric_baseline(train, val, ["dst_port"]),
        "bytes_only": _numeric_baseline(train, val, ["bytes_total", "src_bytes", "dst_bytes"]),
        "duration_only": _numeric_baseline(train, val, ["duration"]),
        "rate_only": _numeric_baseline(
            train,
            val,
            ["connections_1m", "connections_5m", "connections_15m", "connections_1h", "connections_24h"],
        ),
        "time_only": _numeric_baseline(train, val, ["hour_sin", "hour_cos", "is_weekend"]),
        "protocol_only": _categorical_baseline(train, val, "app_proto"),
    }
    risks: list[str] = []
    for name, result in baselines.items():
        if result.get("status") != "ok":
            continue
        pr = float(result["pr_auc"])
        if pr >= high_shortcut_auc or pr >= float(full_model_pr_auc) - tolerance:
            risks.append(name)
    return {
        "full_model_pr_auc": float(full_model_pr_auc),
        "tolerance": float(tolerance),
        "high_shortcut_auc": float(high_shortcut_auc),
        "baselines": baselines,
        "shortcut_risk": bool(risks),
        "risk_baselines": risks,
        "policy": "flag if shortcut PR-AUC >= 0.90 or within 0.02 of full M1 validation PR-AUC",
    }
