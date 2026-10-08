from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--features", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    bundle = joblib.load(args.model)
    df = pd.read_parquet(args.features)
    cols = list(bundle["features"])
    x = df.select_dtypes(include=[np.number, "bool"]).copy()
    for col in cols:
        if col not in x.columns:
            x[col] = 0
    x = x[cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    raw = bundle["model"].predict_proba(x)[:, 1]
    calibrator = bundle.get("calibrator")
    score = calibrator.predict(raw) if calibrator is not None else raw
    threshold = float(bundle.get("threshold", 0.5))

    ranked = pd.DataFrame(
        {
            "campaign_id": df["campaign_id"].astype(str),
            "malicious_probability": score,
            "evaded_threshold": score < threshold,
        }
    ).sort_values("malicious_probability")
    ranked.to_parquet(Path(args.out).with_suffix(".parquet"), index=False)

    evaded = int((score < threshold).sum())
    report = {
        "method": "black_box_gradient_free_random_nuisance_search_on_real_generated_sessions",
        "model": bundle.get("name", "B3-opaque"),
        "sessions": int(len(df)),
        "threshold": threshold,
        "evaded": evaded,
        "attack_success_rate": evaded / max(1, len(df)),
        "score_min": float(np.min(score)) if len(score) else None,
        "score_median": float(np.median(score)) if len(score) else None,
        "score_p95": float(np.quantile(score, 0.95)) if len(score) else None,
        "lowest_50": ranked.head(50).to_dict(orient="records"),
        "holdout_only": True,
    }
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps({"sessions": len(df), "evaded": evaded, "asr": report["attack_success_rate"]}))


if __name__ == "__main__":
    main()
