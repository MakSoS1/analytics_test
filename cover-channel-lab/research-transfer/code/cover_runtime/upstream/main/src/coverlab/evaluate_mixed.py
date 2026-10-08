from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score

from .train_baseline_v2 import build_frames, numeric_matrix


def _score(bundle: dict, frame: pd.DataFrame) -> dict:
    if frame.empty:
        return {"rows": 0}
    model = bundle["model"]
    calibrator = bundle.get("calibrator")
    threshold = float(bundle.get("threshold", 0.5))
    features = list(bundle["features"])
    x, _ = numeric_matrix(frame, features)
    raw = model.predict_proba(x)[:, 1]
    prob = calibrator.predict(raw) if calibrator is not None else raw
    y = frame.label_binary.astype(int).to_numpy()
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    negatives = int((y == 0).sum())
    positives = int((y == 1).sum())
    fpr = float(fp / negatives) if negatives else 0.0
    return {
        "rows": int(len(y)),
        "positives": positives,
        "negatives": negatives,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "fpr": fpr,
        "false_positives_per_million": float(fpr * 1_000_000),
        "alerts_per_10k_objects": float(pred.sum() / max(1, len(pred)) * 10_000),
        "threshold": threshold,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-root", required=True)
    ap.add_argument("--models", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.dataset_root)
    model_root = Path(args.models)
    frames = build_frames(root)
    report = {"evaluation_stage": "D_mixed_frozen_evaluation_only", "models": {}}
    for name, frame in frames.items():
        path = model_root / f"{name}.joblib"
        if not path.exists():
            report["models"][name] = {"status": "missing_model"}
            continue
        bundle = joblib.load(path)
        report["models"][name] = {"status": "ok", **_score(bundle, frame)}

    # Production-like acceptance is most meaningful for session/opaque experts;
    # B1 is transaction-level and its denominator is different.
    evaluated = [
        r for n, r in report["models"].items()
        if n in {"B2-session", "B3-opaque"} and r.get("status") == "ok" and r.get("positives", 0) > 0
    ]
    report["session_acceptance"] = {
        "target_recall": 0.95,
        "target_fp_per_million": 50.0,
        "passed": bool(evaluated) and all(
            r.get("recall", 0.0) >= 0.95 and r.get("false_positives_per_million", float("inf")) <= 50.0
            for r in evaluated
        ),
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
