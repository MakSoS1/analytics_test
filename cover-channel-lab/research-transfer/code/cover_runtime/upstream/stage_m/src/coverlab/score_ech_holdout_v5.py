from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from .train_baseline_v2 import numeric_matrix
from .train_baseline_v3 import availability_flags_v3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--features-root", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out-manifest", required=True)
    args = ap.parse_args()

    root = Path(args.evidence_root)
    manifest_path = root / "ech_holdout.jsonl"
    rows = [json.loads(x) for x in manifest_path.read_text().splitlines() if x.strip()]
    manifest = pd.DataFrame(rows)
    parts = list(Path(args.features_root).rglob("session_features.parquet"))
    features = pd.concat([pd.read_parquet(p) for p in parts], ignore_index=True) if parts else pd.DataFrame()
    if not features.empty:
        features = availability_flags_v3(features)
    bundle = joblib.load(args.model)
    threshold = float(bundle.get("threshold", 0.5))

    merged = manifest.merge(features, on="campaign_id", how="left", suffixes=("", "_feature"))
    if merged.empty or merged["campaign_id"].isna().all():
        raise SystemExit("no ECH evidence rows")
    x, _ = numeric_matrix(merged, list(bundle["features"]))
    raw = bundle["model"].predict_proba(x)[:, 1]
    calibrator = bundle.get("calibrator")
    score = calibrator.predict(raw) if calibrator is not None else raw

    by_id = {str(cid): float(s) for cid, s in zip(merged.campaign_id.astype(str), score)}
    for row in rows:
        cid = str(row["campaign_id"])
        row["model_score"] = by_id[cid]
        row["decision_threshold"] = threshold

    out = Path(args.out_manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r, separators=(",", ":"), sort_keys=True) for r in rows) + "\n")
    print(json.dumps({"records": len(rows), "threshold": threshold}, sort_keys=True))


if __name__ == "__main__":
    main()
