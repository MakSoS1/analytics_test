#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adminlab.modeling import train_supervised
from adminlab.v2_modeling import assert_feature_frame_safe, session_shortcut_audit


def train_view(name: str, path: Path, out: Path, seed: int, *, v2_safe: bool) -> dict:
    frame = pd.read_parquet(path)
    required = {"label_binary", "split"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{name} matrix missing {sorted(missing)}")
    feature_frame = frame.drop(columns=["label_binary", "split"])
    if v2_safe:
        assert_feature_frame_safe(feature_frame)
    model, metrics = train_supervised(frame, seed=seed)
    joblib.dump(model, out / f"{name}.joblib")
    (out / f"{name}.metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flow", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/v2_research.yaml"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=2026081402)
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    args.out.mkdir(parents=True, exist_ok=True)
    metrics = {
        "flow-baseline": train_view("flow-baseline", args.flow, args.out, args.seed, v2_safe=False),
        "session-primary": train_view("session-primary", args.session, args.out, args.seed, v2_safe=True),
        "campaign-primary": train_view("campaign-primary", args.campaign, args.out, args.seed, v2_safe=True),
    }

    session_matrix = pd.read_parquet(args.session)
    session_val = metrics["session-primary"].get("splits", {}).get("validation", {})
    full_pr = float(session_val.get("pr_auc", 0.0))
    shortcut = session_shortcut_audit(
        session_matrix,
        full_model_pr_auc=full_pr,
        required_margin=float(cfg["shortcut_margin_min"]),
    )
    (args.out / "shortcut-audit.json").write_text(
        json.dumps(shortcut, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    summary = {
        "schema_version": 2,
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
        "training_environment": "linux_v2_only",
        "external_holdouts_used_for_training": False,
    }
    (args.out / "V2_MODEL_SUMMARY.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
