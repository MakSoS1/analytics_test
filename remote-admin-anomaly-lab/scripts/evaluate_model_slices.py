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

from adminlab.slice_evaluation import evaluate_slices  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--model-matrix", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20260814)
    args = parser.parse_args()

    matrix = pd.read_parquet(args.model_matrix).reset_index(drop=True)
    labels = pd.read_parquet(args.labels).reset_index(drop=True)
    if len(matrix) != len(labels):
        raise SystemExit(f"matrix/labels row mismatch: {len(matrix)} != {len(labels)}")
    if not {"label_binary", "split"} <= set(matrix.columns):
        raise SystemExit("matrix missing label/split")
    if not {"label_binary", "split"} <= set(labels.columns):
        raise SystemExit("labels missing label/split")
    if not matrix["label_binary"].astype(int).equals(labels["label_binary"].astype(int)):
        raise SystemExit("matrix/labels label alignment mismatch")
    if not matrix["split"].astype(str).equals(labels["split"].astype(str)):
        raise SystemExit("matrix/labels split alignment mismatch")

    model = joblib.load(args.model)
    x = matrix.drop(columns=["label_binary", "split"])
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(x)[:, 1]
    elif hasattr(model, "score"):
        scores = model.score(x)
    else:
        raise SystemExit("model has no supported scoring interface")
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    threshold = float(metrics["threshold"])
    report = evaluate_slices(labels, scores, threshold=threshold, bootstrap_samples=args.bootstrap, seed=args.seed)
    report["model"] = args.model.name
    report["rows"] = int(len(matrix))
    report["alignment"] = "row-order validated by label and split equality; labels retain flow_uid/session_id separately"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
