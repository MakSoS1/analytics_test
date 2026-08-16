from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

HARD_TASKS = {"emergency_admin", "approved_forwarding", "backup", "fix_incident"}
HARD_RELATIONS = {
    "novel_but_ticketed",
    "recently_added_pair",
    "approved_new_pair",
    "known_or_expected_pair",
}
HARD_FAMILIES = {
    "scheduled_patch_fanout",
    "helpdesk",
    "backup_burst",
    "benign_first_seen",
    "offhours_emergency",
    "service_automation",
}


def hard_benign_mask(labels: pd.DataFrame) -> pd.Series:
    if "label_binary" not in labels.columns:
        raise ValueError("labels require label_binary")
    mask = labels["label_binary"].astype(int).eq(0)
    context = pd.Series(False, index=labels.index)
    if "task_id" in labels.columns:
        context |= labels["task_id"].fillna("").astype(str).isin(HARD_TASKS)
    if "historical_relation" in labels.columns:
        context |= labels["historical_relation"].fillna("").astype(str).isin(HARD_RELATIONS)
    if "campaign_type" in labels.columns:
        context |= labels["campaign_type"].fillna("").astype(str).isin(HARD_FAMILIES)
    return mask & context


def evaluate_hard_benign(labels: pd.DataFrame, scores: np.ndarray, *, threshold: float) -> dict[str, Any]:
    if len(labels) != len(scores):
        raise ValueError("labels/scores length mismatch")
    mask = hard_benign_mask(labels)
    subset = labels[mask].copy()
    subset["score"] = np.asarray(scores, dtype=float)[mask.to_numpy()]
    if subset.empty:
        return {"status": "unavailable", "reason": "no hard benign rows", "n": 0}
    pred = (subset["score"].to_numpy(dtype=float) >= float(threshold)).astype(int)
    fp = int(pred.sum())
    n = int(len(subset))
    result: dict[str, Any] = {
        "status": "ok",
        "n": n,
        "false_positives": fp,
        "fpr": float(fp / n),
        "fp_per_10k_hard_benign": float(10000.0 * fp / n),
        "threshold": float(threshold),
    }
    for field in ("task_id", "historical_relation", "campaign_type"):
        if field in subset.columns:
            result[f"by_{field}"] = {
                str(value): {
                    "n": int(len(part)),
                    "false_positives": int((part["score"] >= threshold).sum()),
                    "fpr": float((part["score"] >= threshold).mean()),
                }
                for value, part in subset.groupby(field, dropna=False, sort=True)
            }
    return result
