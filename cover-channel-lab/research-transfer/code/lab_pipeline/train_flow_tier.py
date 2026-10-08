#!/usr/bin/env python3
"""Train the flow-tier binary detector and export it for the SPAN host.

Same honest split as train_lab_binary.py (train campaign_01+02, val 03, test 04)
but on per-flow rows and only the features an NGFW/Suricata EVE can export.
This is the model that can be scored against real office traffic, so it — not
the packet-level one — is what an FPR number may be quoted from.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_tier import FLOW_TIER_FEATURES, export_forest  # noqa: E402

TRAIN_CAMPAIGNS = ("campaign_01", "campaign_02")
VAL_CAMPAIGN = "campaign_03"
TEST_CAMPAIGN = "campaign_04"


def load(path: Path) -> list[dict[str, Any]]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def matrix(rows: list[dict[str, Any]]):
    x = [[float(r.get(f) or 0.0) for f in FLOW_TIER_FEATURES] for r in rows]
    y = [int(float(r.get("y") or 0)) for r in rows]
    return x, y


def metrics_at(y: list[int], p: list[float], thr: float) -> dict[str, float]:
    tp = sum(1 for a, b in zip(y, p) if b >= thr and a == 1)
    fp = sum(1 for a, b in zip(y, p) if b >= thr and a == 0)
    fn = sum(1 for a, b in zip(y, p) if b < thr and a == 1)
    tn = sum(1 for a, b in zip(y, p) if b < thr and a == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": prec,
        "recall": rec,
        "f1": (2 * prec * rec / (prec + rec)) if prec + rec else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n_pos": tp + fn, "n_neg": fp + tn,
    }


def pick_threshold(y: list[int], p: list[float], max_fpr: float) -> float:
    """Lowest threshold whose val FPR still fits the budget (plan §50)."""
    best = 0.5
    for cand in sorted({round(v, 4) for v in p} | {0.5}):
        m = metrics_at(y, p, cand)
        if m["fpr"] <= max_fpr:
            best = cand
            break
    return best


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features-csv", default="/opt/tunnel_lab/features/lab_flow_features.csv")
    ap.add_argument("--out-json", default="/opt/tunnel_lab/features/flow_tier_report.json")
    ap.add_argument("--out-model", default="/opt/tunnel_lab/features/flow_tier_model.json")
    ap.add_argument("--max-fpr", type=float, default=1e-3)
    ap.add_argument("--trees", type=int, default=60)
    ap.add_argument("--max-depth", type=int, default=10)
    args = ap.parse_args()

    rows = load(Path(args.features_csv))
    tr = [r for r in rows if r["campaign_id"] in TRAIN_CAMPAIGNS]
    va = [r for r in rows if r["campaign_id"] == VAL_CAMPAIGN]
    te = [r for r in rows if r["campaign_id"] == TEST_CAMPAIGN]
    report: dict[str, Any] = {
        "n_rows": len(rows),
        "features": FLOW_TIER_FEATURES,
        "n_train": len(tr), "n_val": len(va), "n_test": len(te),
        "notes": [],
    }
    if not tr or not va:
        report["status"] = "insufficient_train_val"
        Path(args.out_json).write_text(json.dumps(report, indent=2))
        print(json.dumps({"status": report["status"]}))
        return 1

    from sklearn.ensemble import RandomForestClassifier

    xtr, ytr = matrix(tr)
    clf = RandomForestClassifier(
        n_estimators=args.trees, max_depth=args.max_depth, random_state=0, n_jobs=-1
    ).fit(xtr, ytr)

    xva, yva = matrix(va)
    pva = [float(v) for v in clf.predict_proba(xva)[:, 1]]
    thr = pick_threshold(yva, pva, args.max_fpr)
    report["threshold"] = thr
    report["val"] = metrics_at(yva, pva, thr)
    if te:
        xte, yte = matrix(te)
        pte = [float(v) for v in clf.predict_proba(xte)[:, 1]]
        report["test"] = metrics_at(yte, pte, thr)
    imp = sorted(zip(FLOW_TIER_FEATURES, clf.feature_importances_), key=lambda x: -x[1])
    report["feature_importance"] = [[n, float(v)] for n, v in imp]
    report["status"] = "ok"
    report["notes"].append(
        "flow-tier only (no first-N sequence): this is the model that can be scored on EVE"
    )

    model = export_forest(clf, FLOW_TIER_FEATURES)
    model["threshold"] = thr
    Path(args.out_model).write_text(json.dumps(model))
    Path(args.out_json).write_text(json.dumps(report, indent=2))
    print(json.dumps({
        "status": "ok", "threshold": thr,
        "val": report["val"], "test": report.get("test"),
        "model": args.out_model,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
