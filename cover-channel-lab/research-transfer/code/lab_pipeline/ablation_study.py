#!/usr/bin/env python3
"""Ablations that say where the signal actually lives.

Existing measurements this replaces or extends:

* Removing `iat_*` alone was called a time ablation. It is not — `flow_duration`,
  `pkt_rate`, `byte_rate`, `burst_count` and `idle_ratio` are all time-derived.
  The honest version dropped lab FPR from 0.0032 to 0.1369, a factor of 43, while
  recall barely moved. Timing was carrying precision, not detection.
* On the same corpus a single rule, `iat_3 < 1108 us`, scored accuracy 0.9886 by
  itself. When one feature does that, the question is what the model is reading,
  and only ablations answer it.

Each run trains the same forest on the same split and changes only the feature
set, so a difference is the cost of those features and not of a different model.
Every result is reported per family as well as micro, because a family at 0.69
disappears inside a flow-weighted mean.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Callable

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.evaluate_alerts import evaluate, wilson_interval  # noqa: E402
from lab_pipeline.flow_tier import export_forest  # noqa: E402
from lab_pipeline.model_bundle import stamp_contract  # noqa: E402
from lab_pipeline.online_schema import FEATURE_NAMES  # noqa: E402
from lab_pipeline.split_manifest import (  # noqa: E402
    InsufficientSplitGroups,
    build_split,
    rows_for_role,
)

TIME_DERIVED_EXACT = {"observed_duration", "iat_mean", "iat_std", "iat_min", "iat_max"}
TIME_DERIVED_PREFIX = ("iat_",)


def is_sequence(name: str) -> bool:
    return name.rsplit("_", 1)[0] in {"signed_len", "dir", "iat", "mask"} and name[-1].isdigit()


def is_time_derived(name: str) -> bool:
    return name in TIME_DERIVED_EXACT or name.startswith(TIME_DERIVED_PREFIX)


ABLATIONS: dict[str, Callable[[str], bool]] = {
    "all": lambda n: True,
    "sequence_only": is_sequence,
    "aggregates_only": lambda n: not is_sequence(n),
    "no_iat_only": lambda n: not n.startswith("iat_"),
    "no_time_at_all": lambda n: not is_time_derived(n),
    "sizes_and_directions_only": lambda n: (
        n.startswith(("signed_len_", "dir_", "mask_"))
        or n in {"pkt_len_mean", "pkt_len_std", "pkt_len_min", "pkt_len_max",
                 "up_bytes", "down_bytes", "total_bytes", "direction_changes"}
    ),
    "first_5_packets_only": lambda n: (
        not is_sequence(n) or int(n.rsplit("_", 1)[1]) < 5
    ),
    "first_10_packets_only": lambda n: (
        not is_sequence(n) or int(n.rsplit("_", 1)[1]) < 10
    ),
}


def load(path: Path) -> list[dict[str, Any]]:
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    with opener(path, "rt") as fh:
        return list(csv.DictReader(fh))


def run_one(name: str, feats: list[str], lab_tr, off_tr, lab_te, off_te,
            off_va, trees: int, depth: int, max_fpr: float, floor: float) -> dict[str, Any]:
    from sklearn.ensemble import RandomForestClassifier

    def mat(rows):
        return [[float(r.get(f) or 0.0) for f in feats] for r in rows]

    ytr = [int(float(r.get("y") or 0)) for r in lab_tr] + [0] * len(off_tr)
    clf = RandomForestClassifier(n_estimators=trees, max_depth=depth,
                                 class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    clf.fit(mat(lab_tr) + mat(off_tr), ytr)

    va = [float(v[1]) for v in clf.predict_proba(mat(off_va))] if off_va else []
    ordered = sorted(va, reverse=True)
    allowed = int(len(ordered) * max_fpr)
    thr = 0.5 if not ordered else (0.0 if allowed >= len(ordered) else min(1.0, ordered[allowed] + 1e-9))

    model = stamp_contract(export_forest(clf, feats))
    model["threshold"] = thr
    rep = evaluate(model, lab_te, off_te, thr, family_recall_floor=floor, max_fpr=max_fpr)
    worst = rep["per_family"][0] if rep["per_family"] else {}
    return {
        "ablation": name,
        "n_features": len(feats),
        "threshold": thr,
        "micro_recall": round(rep["micro_recall"], 4),
        "macro_recall": round(rep["macro_recall"], 4),
        "lab_fpr": rep["lab_benign"]["fpr"],
        "office_fpr": rep.get("office", {}).get("fpr"),
        "office_fpr_upper95": rep.get("office", {}).get("fpr_ci95", [None, None])[1],
        "worst_family": worst.get("family"),
        "worst_family_recall": round(worst.get("flow_recall", 0.0), 4),
        "families_below_floor": rep["families_below_floor"],
        "production_ready": rep["production_ready"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab-csv", required=True)
    ap.add_argument("--office-csv", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--only", nargs="*", default=None, help="subset of ablation names")
    ap.add_argument("--trees", type=int, default=80)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--max-fpr", type=float, default=1e-4)
    ap.add_argument("--family-recall-floor", type=float, default=0.95)
    ap.add_argument("--salt", default="fastv1-v1")
    args = ap.parse_args()

    lab = [r for r in load(Path(args.lab_csv)) if str(r.get("scorable", "1")) == "1"]
    office = [r for r in load(Path(args.office_csv)) if str(r.get("scorable", "1")) == "1"]
    for r in office:
        r["y"] = 0

    roles = {"train": 0.5, "validation": 0.25, "test": 0.25}
    try:
        ls = build_split(lab, "session_id", roles, salt=args.salt)
        os_ = build_split(office, "capture_id", roles, salt=args.salt)
    except InsufficientSplitGroups as exc:
        print(json.dumps({"status": "insufficient_split_groups", "detail": str(exc)}))
        return 3

    lab_tr, lab_te = rows_for_role(lab, ls, "train"), rows_for_role(lab, ls, "test")
    off_tr = rows_for_role(office, os_, "train")
    off_va = rows_for_role(office, os_, "validation")
    off_te = rows_for_role(office, os_, "test")

    wanted = args.only or list(ABLATIONS)
    results = []
    for name in wanted:
        pred = ABLATIONS.get(name)
        if pred is None:
            continue
        feats = [f for f in FEATURE_NAMES if pred(f)]
        if not feats:
            continue
        results.append(run_one(name, feats, lab_tr, off_tr, lab_te, off_te,
                               off_va, args.trees, args.max_depth,
                               args.max_fpr, args.family_recall_floor))

    base = next((r for r in results if r["ablation"] == "all"), None)
    if base:
        for r in results:
            r["delta_macro_recall_vs_all"] = round(r["macro_recall"] - base["macro_recall"], 4)
            if r["lab_fpr"] is not None and base["lab_fpr"]:
                r["lab_fpr_ratio_vs_all"] = round(r["lab_fpr"] / base["lab_fpr"], 2)

    out = {
        "results": results,
        "note": ("each row trains the same forest on the same split and changes only the "
                 "feature set, so a difference is the cost of those features"),
    }
    Path(args.out_json).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "ablations": len(results), "report": args.out_json}))
    for r in results:
        print(f"  {r['ablation']:<28} feats={r['n_features']:>4} "
              f"macro={r['macro_recall']:.3f} labFPR={r['lab_fpr']} "
              f"worst={r['worst_family']}:{r['worst_family_recall']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
