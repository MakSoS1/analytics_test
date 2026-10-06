#!/usr/bin/env python3
"""Train tunnel-vs-benign on lab features (plan v3 §37, §42).

Campaign holdout: 01+02 train, 03 val, 04 test. Threshold is chosen on val
only. Refuses to publish production KPI if test is too small (plan §7.2).
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
from lab_pipeline.schema import LABEL_COLUMNS, LEAKAGE_FEATURES, MODEL_FEATURE_NAMES  # noqa: E402

MIN_TEST_POS = 50
MIN_TEST_NEG = 50
MIN_TRAIN = 20
MIN_VAL = 10
DEFAULT_MAX_FPR = 1e-3


def load_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _float(row: dict[str, Any], key: str) -> float:
    try:
        return float(row.get(key) or 0.0)
    except ValueError:
        return 0.0


def split_campaigns(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": [], "other": []}
    for row in rows:
        camp = row.get("campaign_id") or ""
        if camp in {"campaign_01", "campaign_02"}:
            buckets["train"].append(row)
        elif camp == "campaign_03":
            buckets["val"].append(row)
        elif camp == "campaign_04":
            buckets["test"].append(row)
        else:
            buckets["other"].append(row)
    return buckets


def model_feature_names() -> list[str]:
    return [n for n in MODEL_FEATURE_NAMES if n not in LEAKAGE_FEATURES and n not in LABEL_COLUMNS]


def feature_matrix(rows: list[dict[str, Any]]) -> tuple[list[list[float]], list[int], list[str]]:
    names = model_feature_names()
    x: list[list[float]] = []
    y: list[int] = []
    for row in rows:
        x.append([_float(row, n) for n in names])
        y.append(int(float(row.get("y") or (1 if row.get("label_binary") == "tunnel" else 0))))
    return x, y, names


def fit_rf(train_x: list[list[float]], train_y: list[int]):
    from sklearn.ensemble import RandomForestClassifier

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(train_x, train_y)
    return clf


def predict_pos(clf, eval_x: list[list[float]]) -> list[float]:
    proba = clf.predict_proba(eval_x)
    idx = list(clf.classes_).index(1) if 1 in list(clf.classes_) else 0
    return [float(p[idx]) for p in proba]


def pick_threshold(val_y: list[int], val_p: list[float], max_fpr: float = DEFAULT_MAX_FPR) -> float:
    """Highest recall at FPR <= max_fpr on val; fallback 0.5."""
    n_neg = sum(1 for y in val_y if y == 0)
    n_pos = sum(1 for y in val_y if y == 1)
    if n_neg == 0 or n_pos == 0:
        return 0.5
    pairs = sorted(zip(val_p, val_y), reverse=True)
    tp = fp = 0
    best = (0.0, 0.5)
    for p, y in pairs:
        if y == 1:
            tp += 1
        else:
            fp += 1
        fpr = fp / n_neg
        rec = tp / n_pos
        if fpr <= max_fpr and rec >= best[0]:
            best = (rec, float(p))
    return float(best[1])


def metrics_at(y: list[int], p: list[float], thr: float) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for yi, pi in zip(y, p):
        pred = int(pi >= thr)
        if pred == 1 and yi == 1:
            tp += 1
        elif pred == 1 and yi == 0:
            fp += 1
        elif pred == 0 and yi == 0:
            tn += 1
        else:
            fn += 1
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 0.0 if prec + rec == 0 else 2 * prec * rec / (prec + rec)
    fpr = fp / max(fp + tn, 1)
    return {
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n": len(y),
        "n_pos": sum(y),
        "n_neg": len(y) - sum(y),
        "threshold": thr,
    }


def _stack_variant(row: dict[str, Any]) -> str:
    raw = str(row.get("stack_variant") or "A").strip().upper()
    return raw if raw in {"A", "B"} else "A"


def evaluate_version_holdout(rows: list[dict[str, Any]], max_fpr: float = DEFAULT_MAX_FPR) -> dict[str, Any]:
    """Train on stack_variant=A, evaluate on B (plan v3 version holdout)."""
    a = [r for r in rows if _stack_variant(r) == "A"]
    b = [r for r in rows if _stack_variant(r) == "B"]
    report: dict[str, Any] = {
        "n_A": len(a),
        "n_B": len(b),
        "status": "skipped",
        "notes": [],
    }
    if len(b) < 10 or len(a) < MIN_TRAIN:
        report["notes"].append("need stack_variant A train (≥20) and B eval (≥10)")
        return report
    a_train = [r for r in a if (r.get("campaign_id") or "") in {"campaign_01", "campaign_02"}]
    a_val = [r for r in a if (r.get("campaign_id") or "") == "campaign_03"]
    if len(a_train) < MIN_TRAIN:
        a_train = a[: max(MIN_TRAIN, int(0.7 * len(a)))]
        a_val = a[len(a_train) :]
    if len(a_val) < MIN_VAL:
        report["notes"].append("not enough variant-A val rows")
        return report
    try:
        train_x, train_y, _ = feature_matrix(a_train)
        val_x, val_y, _ = feature_matrix(a_val)
        test_x, test_y, _ = feature_matrix(b)
        clf = fit_rf(train_x, train_y)
    except ImportError:
        report["status"] = "sklearn_missing"
        report["notes"].append("install scikit-learn on the host that trains")
        return report
    val_p = predict_pos(clf, val_x)
    thr = pick_threshold(val_y, val_p, max_fpr=max_fpr)
    test_p = predict_pos(clf, test_x)
    report["status"] = "ok"
    report["val"] = metrics_at(val_y, val_p, thr)
    report["test"] = metrics_at(test_y, test_p, thr)
    report["notes"].append("train A / eval B; not a production KPI by itself")
    return report


def evaluate(rows: list[dict[str, Any]], max_fpr: float = DEFAULT_MAX_FPR) -> dict[str, Any]:
    splits = split_campaigns(rows)
    test_y = [int(float(r.get("y") or 0)) for r in splits["test"]]
    n_pos = sum(test_y)
    n_neg = len(test_y) - n_pos
    report: dict[str, Any] = {
        "n_rows": len(rows),
        "by_campaign": dict(Counter(r.get("campaign_id") for r in rows)),
        "by_binary": dict(Counter(r.get("label_binary") for r in rows)),
        "n_train": len(splits["train"]),
        "n_val": len(splits["val"]),
        "n_test": len(splits["test"]),
        "test_pos": n_pos,
        "test_neg": n_neg,
        "status": "ok",
        "kpi_publishable": False,
        "notes": [],
        "features": model_feature_names(),
        "n_features": len(model_feature_names()),
        "leakage_dropped": sorted(LEAKAGE_FEATURES),
        "model": "RandomForestClassifier",
        "max_fpr_target": max_fpr,
        "version_holdout": evaluate_version_holdout(rows, max_fpr=max_fpr),
    }
    if len(splits["train"]) < MIN_TRAIN or len(splits["val"]) < MIN_VAL:
        report["status"] = "insufficient_train_val"
        report["notes"].append("need campaign_01/02 train and campaign_03 val")
        return report

    val_neg = sum(1 for r in splits["val"] if int(float(r.get("y") or 0)) == 0)
    if val_neg < (1.0 / max_fpr):
        report["notes"].append(
            f"val negatives={val_neg} cannot resolve FPR≤{max_fpr}; threshold is a placeholder"
        )

    try:
        train_x, train_y, names = feature_matrix(splits["train"])
        val_x, val_y, _ = feature_matrix(splits["val"])
        clf = fit_rf(train_x, train_y)
    except ImportError:
        # A test set too small to support a KPI is a fact about the data and
        # holds whether or not this host can train, so report that first —
        # otherwise a missing sklearn masks the real blocker.
        if n_pos < MIN_TEST_POS or n_neg < MIN_TEST_NEG:
            report["status"] = "insufficient_test_data"
            report["notes"].append(
                f"test_pos={n_pos} test_neg={n_neg}; plan §7.2 requires ≥{MIN_TEST_POS} each before KPI"
            )
        else:
            report["status"] = "sklearn_missing"
            report["notes"].append("install scikit-learn on the host that trains")
        report["kpi_publishable"] = False
        return report

    val_p = predict_pos(clf, val_x)
    thr = pick_threshold(val_y, val_p, max_fpr=max_fpr)
    report["features"] = names
    report["val"] = metrics_at(val_y, val_p, thr)
    if splits["test"]:
        test_x, test_y2, _ = feature_matrix(splits["test"])
        test_p = predict_pos(clf, test_x)
        report["test"] = metrics_at(test_y2, test_p, thr)

    enough_test = n_pos >= MIN_TEST_POS and n_neg >= MIN_TEST_NEG
    if not enough_test:
        report["status"] = "insufficient_test_data"
        report["notes"].append(
            f"test_pos={n_pos} test_neg={n_neg}; plan §7.2 requires ≥{MIN_TEST_POS} each before KPI"
        )
        report["kpi_publishable"] = False
        return report

    report["kpi_publishable"] = True
    report["status"] = "ok"
    # P/R can be published off a lab holdout; FPR≤1e-4 cannot. Resolving that
    # rate needs at least 1/max_fpr negative decisions, and the lab produces a
    # few hundred. Say so as a field, not only as prose, so a reader cannot mistake
    # a lab FPR of 0.0 for the production criterion being met.
    report["fpr_measurable"] = n_neg >= (1.0 / max_fpr)
    if not report["fpr_measurable"]:
        report["notes"].append(
            f"test_neg={n_neg} < {int(1.0 / max_fpr)}: reported FPR cannot resolve ≤{max_fpr}; "
            "office SPAN benign is required for the production FPR criterion"
        )
    report["notes"].append("lab holdout only; office SPAN FPR is still required before production KPI")
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--features-csv", default="/opt/tunnel_lab/features/lab_v3_features.csv")
    p.add_argument("--out-json", default="/opt/tunnel_lab/features/lab_v3_binary_report.json")
    p.add_argument("--max-fpr", type=float, default=DEFAULT_MAX_FPR)
    args = p.parse_args()
    rows = load_csv(Path(args.features_csv))
    report = evaluate(rows, max_fpr=args.max_fpr)
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {k: report[k] for k in ("status", "kpi_publishable", "n_rows", "n_train", "n_val", "n_test") if k in report}
        )
    )
    if report.get("status") == "sklearn_missing":
        return 4
    if report.get("kpi_publishable"):
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
