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

from adminlab.modeling import train_supervised
from adminlab.v2_modeling import assert_feature_frame_safe
from adminlab.v3_modeling import v3_shortcut_audit


def train_view(name: str, path: Path, out: Path, seed: int, *, safe: bool) -> dict:
    frame = pd.read_parquet(path)
    missing = {"label_binary", "split"} - set(frame.columns)
    if missing:
        raise ValueError(f"{name} matrix missing {sorted(missing)}")
    features = frame.drop(columns=["label_binary", "split"])
    if safe:
        assert_feature_frame_safe(features)
    model, metrics = train_supervised(frame, seed=seed)
    joblib.dump(model, out / f"{name}.joblib")
    (out / f"{name}.metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flow", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=2026081403)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    metrics = {
        "flow-baseline": train_view("flow-baseline", args.flow, args.out, args.seed, safe=False),
        "session-primary": train_view("session-primary", args.session, args.out, args.seed, safe=True),
        "campaign-primary": train_view("campaign-primary", args.campaign, args.out, args.seed, safe=True),
    }
    session_matrix = pd.read_parquet(args.session)
    val = metrics["session-primary"].get("splits", {}).get("validation", {})
    full_pr = float(val.get("pr_auc", 0.0) or 0.0)
    shortcut = v3_shortcut_audit(session_matrix, full_model_pr_auc=full_pr, seed=args.seed)
    (args.out / "shortcut-audit.json").write_text(json.dumps(shortcut, indent=2, sort_keys=True) + "\n")
    summary = {
        "schema_version": 3,
        "primary_view": "session-primary",
        "views": {
            name: {
                "validation_pr_auc": data.get("splits", {}).get("validation", {}).get("pr_auc"),
                "test_pr_auc": data.get("splits", {}).get("test", {}).get("pr_auc"),
                "challenge_pr_auc": data.get("splits", {}).get("challenge", {}).get("pr_auc"),
            }
            for name, data in metrics.items()
        },
        "shortcut_audit": shortcut,
        "training_environment": "linux_v3_only",
        "external_holdouts_used_for_training": False,
    }
    (args.out / "V3_MODEL_SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
