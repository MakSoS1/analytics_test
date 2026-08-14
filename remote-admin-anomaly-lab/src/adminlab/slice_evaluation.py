from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from .evaluation import campaign_bootstrap_ci


def _metrics(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, Any]:
    y = np.asarray(y, dtype=int)
    score = np.asarray(score, dtype=float)
    pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    negatives = fp + tn
    positives = tp + fn
    result: dict[str, Any] = {
        "n": int(len(y)),
        "positive": int(positives),
        "negative": int(negatives),
        "recall": float(tp / positives) if positives else None,
        "fpr": float(fp / negatives) if negatives else None,
        "fp_per_10k_benign": float(10000 * fp / negatives) if negatives else None,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }
    if len(np.unique(y)) == 2:
        result["pr_auc"] = float(average_precision_score(y, score))
        result["roc_auc"] = float(roc_auc_score(y, score))
    return result


def _group_metrics(frame: pd.DataFrame, field: str, threshold: float, *, positives_only: bool = False) -> dict[str, Any]:
    if field not in frame.columns:
        return {}
    out: dict[str, Any] = {}
    for value, part in frame.groupby(field, dropna=False, sort=True):
        if positives_only:
            part = part[part["label_binary"].astype(int) == 1]
        if part.empty:
            continue
        out[str(value)] = _metrics(
            part["label_binary"].astype(int).to_numpy(),
            part["score"].to_numpy(dtype=float),
            threshold,
        )
    return out


def _reason_metrics(frame: pd.DataFrame, threshold: float) -> dict[str, Any]:
    if "challenge_reason" not in frame.columns:
        return {}
    reasons: set[str] = set()
    for text in frame["challenge_reason"].fillna("").astype(str):
        reasons.update(x for x in text.split(",") if x)
    out: dict[str, Any] = {}
    for reason in sorted(reasons):
        mask = frame["challenge_reason"].fillna("").astype(str).map(lambda x: reason in set(x.split(",")))
        part = frame[mask]
        if not part.empty:
            out[reason] = _metrics(
                part["label_binary"].astype(int).to_numpy(),
                part["score"].to_numpy(dtype=float),
                threshold,
            )
    return out


def campaign_detection_metrics(frame: pd.DataFrame, threshold: float) -> dict[str, Any]:
    required = {"campaign_id", "label_binary", "score"}
    if not required <= set(frame.columns):
        return {"status": "unavailable", "reason": f"missing {sorted(required - set(frame.columns))}"}
    suspicious = frame[frame["label_binary"].astype(int) == 1].copy()
    suspicious = suspicious[suspicious["campaign_id"].fillna("").astype(str) != ""]
    if suspicious.empty:
        return {"status": "unavailable", "reason": "no suspicious campaigns"}

    has_time = "start_ts" in suspicious.columns
    if has_time:
        suspicious["_start"] = pd.to_datetime(suspicious["start_ts"], utc=True, errors="coerce")
    campaign_rows: list[dict[str, Any]] = []
    for campaign_id, part in suspicious.groupby("campaign_id", sort=True):
        # Multiple parser flows may map to one session. Campaign detection should
        # not count those repeated flows as extra campaign events.
        session_key = "session_id" if "session_id" in part.columns else None
        if session_key:
            session_scores = part.groupby(session_key, as_index=False).agg(
                score=("score", "max"),
                start_ts=("_start", "min") if has_time else ("score", "size"),
            )
            if not has_time:
                session_scores = session_scores.drop(columns=["start_ts"])
        else:
            session_scores = part[["score"] + (["_start"] if has_time else [])].copy()
            if has_time:
                session_scores = session_scores.rename(columns={"_start": "start_ts"})
        detected = session_scores[session_scores["score"] >= threshold]
        row: dict[str, Any] = {
            "campaign_id": str(campaign_id),
            "detected": bool(not detected.empty),
            "session_count": int(len(session_scores)),
        }
        if has_time and "start_ts" in session_scores.columns and session_scores["start_ts"].notna().any():
            campaign_start = session_scores["start_ts"].min()
            if not detected.empty and detected["start_ts"].notna().any():
                first_detection = detected["start_ts"].min()
                row["time_to_detection_seconds"] = float(max(0.0, (first_detection - campaign_start).total_seconds()))
            else:
                row["time_to_detection_seconds"] = None
        campaign_rows.append(row)

    detected_count = sum(int(row["detected"]) for row in campaign_rows)
    ttd = [float(row["time_to_detection_seconds"]) for row in campaign_rows if row.get("time_to_detection_seconds") is not None]
    return {
        "status": "ok",
        "suspicious_campaigns": int(len(campaign_rows)),
        "detected_campaigns": int(detected_count),
        "campaign_recall": float(detected_count / len(campaign_rows)),
        "time_to_detection_seconds": {
            "available_campaigns": int(len(ttd)),
            "median": float(np.median(ttd)) if ttd else None,
            "p90": float(np.quantile(ttd, 0.90)) if ttd else None,
            "max": float(np.max(ttd)) if ttd else None,
        },
    }


def evaluate_slices(
    labels: pd.DataFrame,
    scores: np.ndarray,
    *,
    threshold: float,
    bootstrap_samples: int = 1000,
    seed: int = 20260814,
) -> dict[str, Any]:
    if len(labels) != len(scores):
        raise ValueError("labels and scores length mismatch")
    required = {"split", "label_binary"}
    if not required <= set(labels.columns):
        raise ValueError(f"labels missing {sorted(required - set(labels.columns))}")
    frame = labels.reset_index(drop=True).copy()
    frame["score"] = np.asarray(scores, dtype=float)
    report: dict[str, Any] = {"threshold": float(threshold), "splits": {}}
    for split in ("validation", "test", "challenge"):
        part = frame[frame["split"].astype(str) == split].copy()
        if part.empty:
            continue
        split_report: dict[str, Any] = {
            "overall": _metrics(part["label_binary"].astype(int).to_numpy(), part["score"].to_numpy(dtype=float), threshold),
            "per_protocol": _group_metrics(part, "protocol", threshold),
            "per_attack_family": _group_metrics(part, "label_family", threshold, positives_only=True),
            "per_semantic_fidelity": _group_metrics(part, "semantic_fidelity", threshold),
            "per_challenge_reason": _reason_metrics(part, threshold) if split == "challenge" else {},
            "campaign_detection": campaign_detection_metrics(part, threshold),
        }
        if "campaign_id" in part.columns and part["campaign_id"].nunique() >= 2 and part["label_binary"].nunique() == 2:
            try:
                split_report["campaign_bootstrap_ci"] = campaign_bootstrap_ci(part, n_bootstrap=bootstrap_samples, seed=seed)
            except ValueError as exc:
                split_report["campaign_bootstrap_ci"] = {"status": "unavailable", "reason": str(exc)}
        else:
            split_report["campaign_bootstrap_ci"] = {"status": "unavailable", "reason": "requires >=2 campaigns and both classes"}
        report["splits"][split] = split_report
    return report
