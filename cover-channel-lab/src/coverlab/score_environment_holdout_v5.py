from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .train_baseline_v2 import numeric_matrix
from .train_baseline_v3 import availability_flags_v3


def metric_cell(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    y = np.asarray(y, dtype=int)
    score = np.asarray(score, dtype=float)
    if not len(y):
        return {"status": "missing", "rows": 0}
    pred = score >= threshold
    pos = y == 1
    neg = y == 0
    tp = int((pred & pos).sum())
    fp = int((pred & neg).sum())
    positives = int(pos.sum())
    negatives = int(neg.sum())
    return {
        "status": "ok" if positives > 0 and negatives > 0 else "single_class",
        "rows": int(len(y)),
        "positives": positives,
        "negatives": negatives,
        "precision": float(tp / max(1, tp + fp)),
        "recall": float(tp / max(1, positives)),
        "fpr": float(fp / max(1, negatives)),
        "false_alerts": fp,
        "threshold": float(threshold),
        "score_p50": float(np.quantile(score, 0.50)),
        "score_p95": float(np.quantile(score, 0.95)),
        "score_p99": float(np.quantile(score, 0.99)),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Score labeled environment-domain session features with the frozen B3 model.")
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--features", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.evidence_root)
    manifest_path = root / "environment_evidence.jsonl"
    manifest = pd.DataFrame(
        [json.loads(x) for x in manifest_path.read_text().splitlines() if x.strip()]
    )
    features = pd.read_parquet(args.features)
    required = {"capture_id", "label_binary"}
    missing = required - set(features.columns)
    if missing:
        raise SystemExit(f"environment features missing columns: {sorted(missing)}")
    if features.empty:
        raise SystemExit("environment feature table is empty")

    features = availability_flags_v3(features)
    merged = features.merge(
        manifest[["capture_id", "client_stack", "server_stack", "network_evidence"]].drop_duplicates("capture_id"),
        on="capture_id",
        how="inner",
        validate="many_to_one",
    )
    if merged.empty:
        raise SystemExit("no environment feature rows matched registered capture_id values")

    bundle = joblib.load(args.model)
    cols = list(bundle["features"])
    x, _ = numeric_matrix(merged, cols)
    raw = bundle["model"].predict_proba(x)[:, 1]
    calibrator = bundle.get("calibrator")
    score = calibrator.predict(raw) if calibrator is not None else raw
    threshold = float(bundle.get("threshold", 0.5))
    merged = merged.copy()
    merged["model_score"] = score
    merged["decision_threshold"] = threshold

    cells: dict[str, dict] = {}
    for column, prefix in (
        ("client_stack", "client"),
        ("server_stack", "server"),
        ("network_evidence", "network"),
    ):
        for value in sorted(v for v in merged[column].fillna("").astype(str).unique() if v):
            mask = merged[column].astype(str).eq(value).to_numpy()
            cells[f"{prefix}:{value}"] = metric_cell(
                merged.loc[mask, "label_binary"].to_numpy(),
                merged.loc[mask, "model_score"].to_numpy(),
                threshold,
            )

    report = {
        "policy_revision": 5,
        "dataset_role": "environment_external_holdout",
        "rows": int(len(merged)),
        "captures": int(merged.capture_id.nunique()),
        "overall": metric_cell(
            merged.label_binary.to_numpy(),
            merged.model_score.to_numpy(),
            threshold,
        ),
        "cells": cells,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    merged.to_parquet(out.with_suffix(".parquet"), index=False)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
