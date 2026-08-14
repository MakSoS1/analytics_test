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

from adminlab.evaluation import shortcut_audit  # noqa: E402
from adminlab.modeling import evaluate_deterministic, train_benign_only, train_supervised  # noqa: E402


def dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-matrix", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260814)
    parser.add_argument("--enforce-shortcut-gate", action="store_true")
    args = parser.parse_args()

    frame = pd.read_parquet(args.model_matrix)
    if frame.empty:
        raise SystemExit("model matrix is empty")
    if not {"label_binary", "split"} <= set(frame.columns):
        raise SystemExit("model matrix must contain label_binary and split")
    args.out.mkdir(parents=True, exist_ok=True)

    m0 = evaluate_deterministic(frame)
    m1_model, m1 = train_supervised(frame, seed=args.seed)
    m2_model, m2 = train_benign_only(frame, seed=args.seed)

    m1_val_pr = float(m1["splits"]["validation"]["pr_auc"])
    shortcuts = shortcut_audit(frame, full_model_pr_auc=m1_val_pr)

    dump_json(args.out / "M0-deterministic.metrics.json", m0)
    dump_json(args.out / "M1-lightgbm.metrics.json", m1)
    dump_json(args.out / "M2-isolation-forest.metrics.json", m2)
    dump_json(args.out / "shortcut-audit.json", shortcuts)
    joblib.dump(m1_model, args.out / "M1-lightgbm.joblib")
    joblib.dump(m2_model, args.out / "M2-isolation-forest.joblib")

    summary = {
        "rows": int(len(frame)),
        "feature_count": int(len(frame.columns) - 2),
        "split_counts": {str(k): int(v) for k, v in frame["split"].value_counts().to_dict().items()},
        "class_counts": {str(k): int(v) for k, v in frame["label_binary"].value_counts().to_dict().items()},
        "models": {"M0": m0, "M1": m1, "M2": m2},
        "shortcut_audit": shortcuts,
        "release_quality": {
            "shortcut_gate_pass": not bool(shortcuts["shortcut_risk"]),
            "enforced": bool(args.enforce_shortcut_gate),
        },
    }
    dump_json(args.out / "summary.json", summary)
    print(json.dumps(summary, sort_keys=True))
    if args.enforce_shortcut_gate and shortcuts["shortcut_risk"]:
        raise SystemExit("shortcut quality gate failed; inspect shortcut-audit.json before release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
