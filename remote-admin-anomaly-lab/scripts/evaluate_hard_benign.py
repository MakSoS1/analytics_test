#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.hard_benign import evaluate_hard_benign  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--model-matrix", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    matrix = pd.read_parquet(args.model_matrix).reset_index(drop=True)
    labels = pd.read_parquet(args.labels).reset_index(drop=True)
    if len(matrix) != len(labels):
        raise SystemExit("matrix/labels length mismatch")
    if not matrix["label_binary"].astype(int).equals(labels["label_binary"].astype(int)):
        raise SystemExit("matrix/labels label mismatch")
    if not matrix["split"].astype(str).equals(labels["split"].astype(str)):
        raise SystemExit("matrix/labels split mismatch")

    model = joblib.load(args.model)
    x = matrix.drop(columns=["label_binary", "split"])
    if not hasattr(model, "predict_proba"):
        raise SystemExit("hard benign evaluator expects supervised probability model")
    scores = model.predict_proba(x)[:, 1]
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    report = evaluate_hard_benign(labels, scores, threshold=float(metrics["threshold"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
