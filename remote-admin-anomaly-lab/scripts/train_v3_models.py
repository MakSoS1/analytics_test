#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
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
from adminlab.v3_modeling import v3_flow_shortcut_audit, v3_shortcut_audit


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
        "flow-primary": train_view("flow-primary", args.flow, args.out, args.seed, safe=False),
        "session-research": train_view("session-research", args.session, args.out, args.seed, safe=True),
        "campaign-research": train_view("campaign-research", args.campaign, args.out, args.seed, safe=True),
    }

    # Stable NGFW alias used by deployment examples/sidecar. It is byte-identical
    # to the authoritative flow-primary model from the same run.
    shutil.copyfile(args.out / "flow-primary.joblib", args.out / "M1-lightgbm.joblib")
    shutil.copyfile(args.out / "flow-primary.metrics.json", args.out / "M1-lightgbm.metrics.json")

    flow_matrix = pd.read_parquet(args.flow)
    flow_val = metrics["flow-primary"].get("splits", {}).get("validation", {})
    flow_pr = float(flow_val.get("pr_auc", 0.0) or 0.0)
    shortcut = v3_flow_shortcut_audit(flow_matrix, full_model_pr_auc=flow_pr, seed=args.seed)
    (args.out / "shortcut-audit.json").write_text(json.dumps(shortcut, indent=2, sort_keys=True) + "\n")

    session_matrix = pd.read_parquet(args.session)
    session_val = metrics["session-research"].get("splits", {}).get("validation", {})
    session_pr = float(session_val.get("pr_auc", 0.0) or 0.0)
    session_shortcut = v3_shortcut_audit(session_matrix, full_model_pr_auc=session_pr, seed=args.seed)
    (args.out / "shortcut-audit-session-research.json").write_text(
        json.dumps(session_shortcut, indent=2, sort_keys=True) + "\n"
    )

    summary = {
        "schema_version": 4,
        "primary_view": "flow-primary",
        "primary_unit": "suricata_eve_flow",
        "deployment_model_alias": "M1-lightgbm.joblib",
        "train_serve_feature_code": "adminlab.online_features.EveFeatureState",
        "views": {
            name: {
                "role": "production_primary" if name == "flow-primary" else "research_only",
                "validation_pr_auc": data.get("splits", {}).get("validation", {}).get("pr_auc"),
                "test_pr_auc": data.get("splits", {}).get("test", {}).get("pr_auc"),
                "challenge_pr_auc": data.get("splits", {}).get("challenge", {}).get("pr_auc"),
            }
            for name, data in metrics.items()
        },
        "shortcut_audit": shortcut,
        "session_research_shortcut_audit": session_shortcut,
        "training_environment": "linux_v3_only",
        "external_holdouts_used_for_training": False,
        "orchestrator_session_boundary_required_at_runtime": False,
    }
    (args.out / "V3_MODEL_SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
