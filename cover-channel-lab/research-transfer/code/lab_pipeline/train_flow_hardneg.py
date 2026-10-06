#!/usr/bin/env python3
"""Flow-tier detector trained with REAL office background as hard negatives.

Why this exists: `train_flow_tier.py` learns from lab negatives only, and a
model trained that way flags a quarter to a third of real office traffic (plan
§47 wants FPR <= 1e-4). The lab negative class — a handful of sites fetched
over curl — does not describe an office: Teams, LDAP, WebSocket, long TLS.

So the negative class here is the office itself, exported de-identified by
`export_office_flows.py` (16 numbers per flow, no IPs).

Splits, and why they are the way they are:
  positives  lab tunnel flows, campaign holdout 01+02 / 03 / 04 (unchanged)
  negatives  lab benign on the same campaign split, PLUS office flows split by
             time bucket: the earliest buckets train, the latest bucket is a
             held-out office slice used for the FPR number.

Office traffic is UNLABELED. Rows carry `y_presumed=0`, not `y`. Any real
tunnel in the office background is label noise pushing recall down, never a
silent true negative — the report states the assumption instead of hiding it.
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
from lab_pipeline.schema import MODEL_FEATURE_NAMES  # noqa: E402
from lab_pipeline.split_manifest import (  # noqa: E402
    InsufficientSplitGroups,
    build_split,
    rows_for_role,
    verify_disjoint,
)

TRAIN_CAMPAIGNS = ("campaign_01", "campaign_02")
VAL_CAMPAIGN = "campaign_03"
TEST_CAMPAIGN = "campaign_04"


def load(path: Path) -> list[dict[str, Any]]:
    opener = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open  # type: ignore[assignment]
    with opener(path, "rt") as fh:  # type: ignore[call-arg]
        return list(csv.DictReader(fh))


FEATURES: list[str] = list(FLOW_TIER_FEATURES)


def matrix(rows: list[dict[str, Any]], label_key: str = "y"):
    x = [[float(r.get(f) or 0.0) for f in FEATURES] for r in rows]
    y = [int(float(r.get(label_key) or 0)) for r in rows]
    return x, y


def metrics_at(y: list[int], p: list[float], thr: float) -> dict[str, Any]:
    tp = sum(1 for a, b in zip(y, p) if b >= thr and a == 1)
    fp = sum(1 for a, b in zip(y, p) if b >= thr and a == 0)
    fn = sum(1 for a, b in zip(y, p) if b < thr and a == 1)
    tn = sum(1 for a, b in zip(y, p) if b < thr and a == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": prec, "recall": rec,
        "f1": (2 * prec * rec / (prec + rec)) if prec + rec else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n_pos": tp + fn, "n_neg": fp + tn,
    }


def pick_threshold_for_fpr(neg_scores: list[float], max_fpr: float) -> float:
    """Smallest threshold whose FPR on the office negatives fits the budget.

    Measured on office rows, not lab rows: the lab has a few hundred negatives
    and cannot resolve 1e-4 at all.
    """
    if not neg_scores:
        return 0.5
    ordered = sorted(neg_scores, reverse=True)
    allowed = int(len(ordered) * max_fpr)
    if allowed >= len(ordered):
        return 0.0
    # Everything strictly above this score is the allowed false-positive budget.
    return min(1.0, ordered[allowed] + 1e-9)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab-csv", required=True, help="lab per-flow features (has y, campaign_id)")
    ap.add_argument("--office-csv", required=True, help="de-identified office flows (y_presumed, time_bucket)")
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-model", required=True)
    ap.add_argument("--max-fpr", type=float, default=1e-4)
    ap.add_argument("--split-salt", default="tunnel-detector-v1")
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--drop-features", default="",
                    help="comma-separated prefixes to exclude, e.g. 'iat_' to ablate the lab RTT artifact")
    ap.add_argument("--tier", choices=("flow", "packet"), default="flow",
                    help="flow = 16 EVE-derivable features; packet = the 112-feature first-20 tier")
    args = ap.parse_args()

    global FEATURES
    FEATURES = list(MODEL_FEATURE_NAMES) if args.tier == "packet" else list(FLOW_TIER_FEATURES)
    dropped = [d.strip() for d in args.drop_features.split(",") if d.strip()]
    if dropped:
        FEATURES = [f for f in FEATURES if not any(f.startswith(d) for d in dropped)]

    from sklearn.ensemble import RandomForestClassifier

    lab = load(Path(args.lab_csv))
    office = load(Path(args.office_csv))

    lab_tr = [r for r in lab if r.get("campaign_id") in TRAIN_CAMPAIGNS]
    lab_va = [r for r in lab if r.get("campaign_id") == VAL_CAMPAIGN]
    lab_te = [r for r in lab if r.get("campaign_id") == TEST_CAMPAIGN]

    # Office rows are split by capture window, never by row position. The old
    # fallback cut the row list at 70% and called it `capture_window_tail_30pct`;
    # rows carried no window id, so that boundary could run through one capture.
    # And the threshold used to come from the rows the forest had just trained on.
    group_key = "capture_id" if any(r.get("capture_id") for r in office) else "time_bucket"
    try:
        osplit = build_split(office, group_key,
                             {"train": 0.5, "validation": 0.25, "test": 0.25},
                             salt=args.split_salt)
        verify_disjoint(osplit)
    except InsufficientSplitGroups as exc:
        print(json.dumps({
            "status": "insufficient_split_groups",
            "detail": str(exc),
            "group_key": group_key,
            "note": "collect office traffic over more capture windows; no row-tail fallback",
        }))
        return 3
    off_tr = rows_for_role(office, osplit, "train")
    off_va = rows_for_role(office, osplit, "validation")
    off_ho = rows_for_role(office, osplit, "test")
    for r in off_tr + off_va + off_ho:
        r["y"] = 0

    xtr, ytr = matrix(lab_tr + off_tr)
    xva, yva = matrix(lab_va)
    xte, yte = matrix(lab_te)
    xoh, _ = matrix(off_ho)
    xot, _ = matrix(off_tr)
    xov, _ = matrix(off_va)

    clf = RandomForestClassifier(
        n_estimators=args.trees, max_depth=args.max_depth,
        class_weight="balanced_subsample", n_jobs=-1, random_state=42,
    )
    clf.fit(xtr, ytr)

    def proba(x):
        return [float(v[1]) for v in clf.predict_proba(x)] if x else []

    p_va, p_te = proba(xva), proba(xte)
    p_oh, p_ot, p_ov = proba(xoh), proba(xot), proba(xov)

    # Threshold comes from the office VALIDATION slice: rows the forest never saw
    # and that are not the final test either.
    thr = pick_threshold_for_fpr(p_ov, args.max_fpr)

    def office_fpr(scores: list[float], t: float) -> dict[str, Any]:
        fp = sum(1 for s in scores if s >= t)
        n = len(scores)
        return {"flagged": fp, "n": n, "fpr": (fp / n) if n else None}

    report: dict[str, Any] = {
        "status": "ok",
        "tier": args.tier,
        "n_features": len(FEATURES),
        "dropped_feature_prefixes": dropped,
        "threshold": thr,
        "max_fpr_target": args.max_fpr,
        "negatives": "lab benign + real office background (unlabeled, presumed negative)",
        "office_split": {
            "group_key": group_key,
            "group_counts": osplit["group_counts"],
            "row_counts": osplit["row_counts"],
            "salt": osplit["salt"],
        },
        "n_lab_train": len(lab_tr), "n_lab_val": len(lab_va), "n_lab_test": len(lab_te),
        "n_office_train": len(off_tr), "n_office_validation": len(off_va),
        "n_office_test": len(off_ho),
        "lab_val": metrics_at(yva, p_va, thr),
        "lab_test": metrics_at(yte, p_te, thr),
        "office_train_fpr": office_fpr(p_ot, thr),
        "office_validation_fpr": office_fpr(p_ov, thr),
        "office_test_fpr": office_fpr(p_oh, thr),
        "feature_importance": sorted(
            zip(FEATURES, (float(v) for v in clf.feature_importances_)),
            key=lambda kv: kv[1], reverse=True,
        ),
        "caveats": [
            "office rows are unlabeled; a real tunnel there is label noise, not a true negative",
            "threshold comes from the office validation slice; the test slice is untouched by it",
        ],
    }

    # What does each alert budget cost in lab recall?
    curve = []
    for target in (1e-2, 1e-3, 1e-4, 1e-5):
        t = pick_threshold_for_fpr(p_ov, target)
        curve.append({
            "office_fpr_target": target,
            "threshold": t,
            "office_test_fpr": office_fpr(p_oh, t)["fpr"],
            "lab_test_recall": metrics_at(yte, p_te, t)["recall"],
            "lab_test_precision": metrics_at(yte, p_te, t)["precision"],
        })
    report["budget_curve"] = curve

    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    model = export_forest(clf, list(FEATURES))
    model["threshold"] = thr
    model["tier"] = args.tier
    Path(args.out_model).write_text(json.dumps(model) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "ok", "threshold": thr,
        "lab_test": {k: report["lab_test"][k] for k in ("precision", "recall", "f1")},
        "office_test_fpr": report["office_test_fpr"],
        "model": args.out_model, "report": args.out_json,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
