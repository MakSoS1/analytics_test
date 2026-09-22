from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .train_baseline_v2 import numeric_matrix


def main() -> None:
    ap = argparse.ArgumentParser(description="Score externally prepared benign office session features with B3.")
    ap.add_argument("--features", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    df = pd.read_parquet(args.features)
    if df.empty:
        raise SystemExit("office feature table is empty")
    bundle = joblib.load(args.model)
    x, _ = numeric_matrix(df, list(bundle["features"]))
    raw = bundle["model"].predict_proba(x)[:, 1]
    calibrator = bundle.get("calibrator")
    score = calibrator.predict(raw) if calibrator is not None else raw
    threshold = float(bundle.get("threshold", 0.5))
    alerts = int((score >= threshold).sum())
    report = {
        "policy_revision": 5,
        "dataset_role": "external_office_benign",
        "rows": int(len(df)),
        "alerts": alerts,
        "fpr": float(alerts / len(df)),
        "false_positives_per_million": float(alerts / len(df) * 1_000_000),
        "score_p50": float(np.quantile(score, 0.50)),
        "score_p95": float(np.quantile(score, 0.95)),
        "score_p99": float(np.quantile(score, 0.99)),
        "threshold": threshold,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
