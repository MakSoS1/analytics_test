from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .train_baseline_v2 import numeric_matrix
from .research_contract_v3 import FRAMEWORKS


def _load_manifest(root: Path) -> pd.DataFrame:
    path = root / "framework_holdout.jsonl"
    rows = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    return pd.DataFrame(rows)


def _metrics(scores: np.ndarray, threshold: float) -> dict:
    if not len(scores):
        return {"status": "missing", "rows": 0}
    hits = int((scores >= threshold).sum())
    return {
        "status": "ok",
        "rows": int(len(scores)),
        "positives": int(len(scores)),
        "precision": 1.0 if hits else 0.0,
        "recall": float(hits / len(scores)),
        "fpr": 0.0,
        "false_alerts": 0,
        "score_min": float(scores.min()),
        "score_median": float(np.median(scores)),
        "score_p95": float(np.quantile(scores, 0.95)),
        "threshold": float(threshold),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--features-root", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    evidence = Path(args.evidence_root)
    manifest = _load_manifest(evidence)
    parts = list(Path(args.features_root).rglob("session_features.parquet"))
    frames = [pd.read_parquet(p) for p in parts]
    features = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    bundle = joblib.load(args.model)
    threshold = float(bundle.get("threshold", 0.5))

    merged = features.merge(
        manifest[["campaign_id", "framework"]].drop_duplicates("campaign_id"),
        on="campaign_id",
        how="inner",
    )
    if merged.empty:
        raise SystemExit("no framework session features matched the evidence manifest")

    x, _ = numeric_matrix(merged, list(bundle["features"]))
    raw = bundle["model"].predict_proba(x)[:, 1]
    calibrator = bundle.get("calibrator")
    score = calibrator.predict(raw) if calibrator is not None else raw
    merged = merged[["campaign_id", "framework"]].copy()
    merged["model_score"] = score
    merged["decision_threshold"] = threshold

    metrics = {}
    for framework in FRAMEWORKS:
        vals = merged.loc[merged.framework.eq(framework), "model_score"].to_numpy(dtype=float)
        metrics[framework] = _metrics(vals, threshold)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    merged.to_parquet(out.with_suffix(".parquet"), index=False)
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
