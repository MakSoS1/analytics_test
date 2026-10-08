#!/usr/bin/env python3
"""Per-family evaluation and a family classifier on the packet-level tier.

Answers two questions the binary detector cannot:

  1. Which tunnel families does the binary detector actually catch, and which
     does it miss? A global recall of 0.94 can still hide a family at 0.2.
  2. Once a flow is flagged, which family is it? Family never blocks an alert
     (plan §1.2) — it is triage, so it is trained and reported separately.

Same honest split as everywhere else: campaign 01+02 train, 03 val, 04 test,
threshold picked on val only. Leave-one-family-out is reported too: train with
one family removed, then measure recall on that unseen family. That is the only
number here that speaks to unknown tunnels.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.flow_tier import export_forest  # noqa: E402
from lab_pipeline.schema import MODEL_FEATURE_NAMES  # noqa: E402

TRAIN_CAMPAIGNS = ("campaign_01", "campaign_02")
VAL_CAMPAIGN = "campaign_03"
TEST_CAMPAIGN = "campaign_04"
MIN_TEST_POS = 50  # plan §7.2: below this a family metric is not publishable


def load(path: Path) -> list[dict[str, Any]]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def matrix(rows: list[dict[str, Any]]):
    x = [[float(r.get(f) or 0.0) for f in MODEL_FEATURE_NAMES] for r in rows]
    y = [1 if r.get("label_binary") == "tunnel" else 0 for r in rows]
    return x, y


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--features-csv", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--skip-lofo", action="store_true")
    ap.add_argument("--out-model-dir", default=None, help="where to write deployable model artifacts")
    args = ap.parse_args()

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score

    rows = load(Path(args.features_csv))
    tr = [r for r in rows if r.get("campaign_id") in TRAIN_CAMPAIGNS]
    va = [r for r in rows if r.get("campaign_id") == VAL_CAMPAIGN]
    te = [r for r in rows if r.get("campaign_id") == TEST_CAMPAIGN]

    xtr, ytr = matrix(tr)
    xva, yva = matrix(va)
    xte, yte = matrix(te)

    def forest(n=args.trees):
        return RandomForestClassifier(
            n_estimators=n, class_weight="balanced_subsample", n_jobs=-1, random_state=42,
        )

    # ---- binary detector, then recall broken out per family -----------------
    clf = forest()
    clf.fit(xtr, ytr)
    p_va = [float(v[1]) for v in clf.predict_proba(xva)]
    p_te = [float(v[1]) for v in clf.predict_proba(xte)]

    # threshold on val only
    best_thr, best_f1 = 0.5, -1.0
    for cand in sorted({round(v, 3) for v in p_va}):
        f1 = f1_score(yva, [1 if s >= cand else 0 for s in p_va], zero_division=0)
        if f1 > best_f1:
            best_thr, best_f1 = cand, f1

    out_dir = Path(args.out_model_dir) if args.out_model_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        bin_model = export_forest(clf, list(MODEL_FEATURE_NAMES))
        bin_model["threshold"] = best_thr
        bin_model["tier"] = "packet_level_112"
        (out_dir / "packet_binary_model.json").write_text(json.dumps(bin_model) + "\n", encoding="utf-8")

    per_family: list[dict[str, Any]] = []
    fam_rows: dict[str, list[int]] = {}
    for r, s in zip(te, p_te):
        if r.get("label_binary") != "tunnel":
            continue
        fam_rows.setdefault(r.get("label_family") or "?", []).append(1 if s >= best_thr else 0)
    for fam, hits in sorted(fam_rows.items()):
        n = len(hits)
        per_family.append({
            "family": fam,
            "test_positives": n,
            "detected": sum(hits),
            "recall": sum(hits) / n if n else 0.0,
            "publishable": n >= MIN_TEST_POS,
        })
    per_family.sort(key=lambda d: d["recall"])

    neg = [(r, s) for r, s in zip(te, p_te) if r.get("label_binary") != "tunnel"]
    fp = sum(1 for _r, s in neg if s >= best_thr)

    report: dict[str, Any] = {
        "threshold": best_thr,
        "n_train": len(tr), "n_val": len(va), "n_test": len(te),
        "binary_test": {
            "recall_overall": sum(d["detected"] for d in per_family) / max(sum(d["test_positives"] for d in per_family), 1),
            "lab_fpr": fp / len(neg) if neg else None,
            "n_neg": len(neg),
        },
        "per_family_recall": per_family,
        "families_below_0.95": [d["family"] for d in per_family if d["recall"] < 0.95],
        "families_not_publishable": [d["family"] for d in per_family if not d["publishable"]],
    }

    # ---- family classifier (triage only, never gates the alert) -------------
    tr_t = [r for r in tr if r.get("label_binary") == "tunnel"]
    te_t = [r for r in te if r.get("label_binary") == "tunnel"]
    if tr_t and te_t:
        xf = [[float(r.get(f) or 0.0) for f in MODEL_FEATURE_NAMES] for r in tr_t]
        yf = [r.get("label_family") or "?" for r in tr_t]
        xg = [[float(r.get(f) or 0.0) for f in MODEL_FEATURE_NAMES] for r in te_t]
        yg = [r.get("label_family") or "?" for r in te_t]
        fam_clf = forest()
        fam_clf.fit(xf, yf)
        pred = list(fam_clf.predict(xg))
        correct = Counter()
        total = Counter()
        for truth, got in zip(yg, pred):
            total[truth] += 1
            if truth == got:
                correct[truth] += 1
        if out_dir:
            import pickle

            (out_dir / "family_classifier.pkl").write_bytes(pickle.dumps(fam_clf))
            (out_dir / "family_classifier_meta.json").write_text(json.dumps({
                "classes": sorted(set(yf)),
                "features": list(MODEL_FEATURE_NAMES),
                "tier": "packet_level_112",
                "note": "triage only; family never gates the alert (plan 1.2)",
            }, indent=2) + "\n", encoding="utf-8")
        report["family_classifier"] = {
            "accuracy": sum(correct.values()) / max(len(yg), 1),
            "macro_f1": float(f1_score(yg, pred, average="macro", zero_division=0)),
            "per_family_accuracy": sorted(
                ({"family": f, "n": total[f], "correct": correct[f], "accuracy": correct[f] / total[f]}
                 for f in total),
                key=lambda d: d["accuracy"],
            ),
        }

    # ---- leave-one-family-out: the only unknown-tunnel number ---------------
    if not args.skip_lofo:
        fams = sorted({r.get("label_family") for r in rows
                       if r.get("label_binary") == "tunnel" and r.get("label_family")})
        lofo = []
        for fam in fams:
            tr_wo = [r for r in tr if r.get("label_family") != fam]
            held = [r for r in (va + te) if r.get("label_family") == fam]
            if len(held) < 10 or not tr_wo:
                continue
            xw, yw = matrix(tr_wo)
            if len(set(yw)) < 2:
                continue
            c = forest(150)
            c.fit(xw, yw)
            ph = [float(v[1]) for v in c.predict_proba(
                [[float(r.get(f) or 0.0) for f in MODEL_FEATURE_NAMES] for r in held])]
            lofo.append({
                "family": fam,
                "held_sessions": len(held),
                "unknown_family_recall": sum(1 for s in ph if s >= best_thr) / len(ph),
            })
        lofo.sort(key=lambda d: d["unknown_family_recall"])
        report["leave_one_family_out"] = lofo

    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "threshold": best_thr,
        "overall_recall": report["binary_test"]["recall_overall"],
        "families_below_0.95": report["families_below_0.95"],
        "family_classifier_accuracy": report.get("family_classifier", {}).get("accuracy"),
        "report": args.out_json,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
