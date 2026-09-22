from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from .score_environment_holdout_v5 import metric_cell
from .train_baseline_v2 import numeric_matrix
from .train_baseline_v3 import availability_flags_v3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--features-root", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    root = Path(a.evidence_root)
    rows = [json.loads(x) for x in (root / "long_timing_evidence.jsonl").read_text().splitlines() if x.strip()]
    manifest = pd.DataFrame(rows)
    parts = list(Path(a.features_root).rglob("session_features.parquet"))
    features = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True) if parts else pd.DataFrame()
    if features.empty:
        raise SystemExit("long timing feature table is empty")
    features = availability_flags_v3(features)
    merged = features.merge(
        manifest[["campaign_id", "real_interval_seconds", "label_binary"]].drop_duplicates("campaign_id"),
        on="campaign_id",
        how="inner",
        suffixes=("", "_manifest"),
        validate="one_to_one",
    )
    if merged.empty:
        raise SystemExit("no long timing features matched evidence campaigns")
    if "label_binary_manifest" in merged:
        merged["label_binary"] = merged["label_binary_manifest"].astype(int)

    bundle = joblib.load(a.model)
    x, _ = numeric_matrix(merged, list(bundle["features"]))
    raw = bundle["model"].predict_proba(x)[:, 1]
    cal = bundle.get("calibrator")
    score = cal.predict(raw) if cal is not None else raw
    threshold = float(bundle.get("threshold", 0.5))
    merged["model_score"] = score
    merged["decision_threshold"] = threshold

    cells = {}
    for interval in (1200, 3600):
        sub = merged.loc[pd.to_numeric(merged.real_interval_seconds, errors="coerce").eq(interval)]
        cells[str(interval)] = metric_cell(
            sub.label_binary.to_numpy(dtype=int),
            sub.model_score.to_numpy(dtype=float),
            threshold,
        )

    report = {
        "policy_revision": 5,
        "dataset_role": "external_long_timing_challenge",
        "rows": int(len(merged)),
        "cells": cells,
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    merged.to_parquet(out.with_suffix(".parquet"), index=False)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
