#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.modeling import build_supervised_pipeline  # noqa: E402


def _rank(value: str, seed: int) -> str:
    return hashlib.sha256(f"{seed}|curve|{value}".encode()).hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model-matrix", type=Path, required=True)
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--seed", type=int, default=20260814)
    args = p.parse_args()

    matrix = pd.read_parquet(args.model_matrix).reset_index(drop=True)
    labels = pd.read_parquet(args.labels).reset_index(drop=True)
    if len(matrix) != len(labels):
        raise SystemExit("matrix/labels length mismatch")
    if not matrix["label_binary"].astype(int).equals(labels["label_binary"].astype(int)):
        raise SystemExit("matrix/labels labels are not aligned")
    if not matrix["split"].astype(str).equals(labels["split"].astype(str)):
        raise SystemExit("matrix/labels splits are not aligned")
    if "campaign_id" not in labels.columns:
        raise SystemExit("campaign_id required for grouped learning curve")

    train_mask = matrix["split"].astype(str).eq("train")
    val_mask = matrix["split"].astype(str).eq("validation")
    train_campaigns = sorted(labels.loc[train_mask, "campaign_id"].astype(str).unique(), key=lambda x: _rank(x, args.seed))
    if len(train_campaigns) < 8:
        raise SystemExit(f"too few train campaigns for learning curve: {len(train_campaigns)}")
    val = matrix[val_mask].copy()
    if val.empty or val["label_binary"].nunique() < 2:
        raise SystemExit("validation split requires both classes")
    x_val = val.drop(columns=["label_binary", "split"])
    y_val = val["label_binary"].astype(int).to_numpy()

    points = []
    for fraction in (0.25, 0.50, 0.75, 1.00):
        n_campaigns = max(2, int(round(len(train_campaigns) * fraction)))
        selected = set(train_campaigns[:n_campaigns])
        row_mask = train_mask & labels["campaign_id"].astype(str).isin(selected)
        subset = matrix[row_mask].copy()
        if subset["label_binary"].nunique() < 2:
            continue
        x_train = subset.drop(columns=["label_binary", "split"])
        y_train = subset["label_binary"].astype(int).to_numpy()
        model = build_supervised_pipeline(x_train, seed=args.seed + n_campaigns)
        model.fit(x_train, y_train)
        score = model.predict_proba(x_val)[:, 1]
        points.append({
            "fraction": fraction,
            "campaigns": int(n_campaigns),
            "train_rows": int(len(subset)),
            "validation_rows": int(len(val)),
            "pr_auc": float(average_precision_score(y_val, score)),
            "roc_auc": float(roc_auc_score(y_val, score)),
        })
    if len(points) < 2:
        raise SystemExit("learning curve produced fewer than two valid points")
    for i in range(1, len(points)):
        points[i]["delta_pr_auc"] = float(points[i]["pr_auc"] - points[i-1]["pr_auc"])
    last_delta = points[-1].get("delta_pr_auc")
    report = {
        "grouping": "campaign_id",
        "points": points,
        "last_delta_pr_auc": last_delta,
        "scale_recommendation": "expand" if last_delta is not None and last_delta > 0.005 else "prefer_diversity_or_holdout_analysis",
        "policy": "scale only when the final grouped learning-curve PR-AUC gain exceeds 0.005",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
