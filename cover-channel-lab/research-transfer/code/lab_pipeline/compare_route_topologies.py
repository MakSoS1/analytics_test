#!/usr/bin/env python3
"""Decide the route topology by measurement, on one split, with the leak checks.

Two candidates, evaluated on the SAME test population so the numbers are
comparable:

* **three_routes** — every TCP flow goes to one model. This is what
  `classify_route` already does, so opaque_outer never receives anything.
* **four_routes** — TCP is split by the only app-layer observable a router
  could actually have: whether the first payload toward the server is a TLS
  ClientHello. TLS-opening flows go to tcp_tls_fast, the rest to opaque_outer.

Both are scored over all TCP test rows at the same per-model lab-benign FPR
budget, and the headline is the WORST family's flow recall, because the release
gate is a floor on every family rather than an average.

The split groups a benign twin with its own tunnel, so a test negative is never
a near-copy of a capture that trained the model.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from lab_pipeline.online_schema import FEATURE_NAMES
from lab_pipeline.split_manifest import build_split, rows_for_role
from lab_pipeline.train_fastv1 import keep_scorable, load, matrix, threshold_for_fpr
from lab_pipeline.train_route_lab import (
    CAPTURE_CELL,
    ROLES,
    family_sample_weights,
    row_route,
    with_capture_cells,
)

TLS_OPENING = "tls_client_hello"


def opening_is_tls(qc: dict) -> dict[str, bool]:
    """Per session: did the first payload toward the server open with TLS?"""
    out: dict[str, bool] = {}
    for row in qc.get("session_verdicts") or []:
        session = str(row.get("session_id") or "")
        if not session:
            continue
        out[session] = TLS_OPENING in (row.get("opening_signatures") or [])
    return out


def arm_of(row: dict[str, Any], tls_by_session: dict[str, bool]) -> str:
    """Which TCP arm a flow belongs to under the four-route topology."""
    return "tls" if tls_by_session.get(str(row.get("session_id") or ""), False) else "opaque"


def _fit(train_rows, seed=42):
    from sklearn.ensemble import RandomForestClassifier

    x_train, y_train = matrix(train_rows)
    if len(set(y_train)) < 2:
        return None
    model = RandomForestClassifier(
        n_estimators=200, max_depth=16, min_samples_leaf=5,
        class_weight=None, n_jobs=2, random_state=seed,
    )
    model.fit(x_train, y_train, sample_weight=family_sample_weights(train_rows))
    return model


def _scores(model, rows):
    if model is None or not rows:
        return []
    x, _ = matrix(rows)
    return [float(p[1]) for p in model.predict_proba(x)]


def _evaluate(flagged: list[tuple[dict[str, Any], bool]]) -> dict[str, Any]:
    per_family: dict[str, dict[str, int]] = defaultdict(lambda: {"rows": 0, "flagged": 0})
    negatives = 0
    false_positives = 0
    for row, hit in flagged:
        if str(row.get("y")) == "1":
            slot = per_family[str(row.get("label_family") or "")]
            slot["rows"] += 1
            slot["flagged"] += int(hit)
        else:
            negatives += 1
            false_positives += int(hit)
    recalls = {
        family: slot["flagged"] / slot["rows"]
        for family, slot in per_family.items() if slot["rows"]
    }
    return {
        "families": len(recalls),
        "worst_family_flow_recall": min(recalls.values(), default=None),
        "mean_family_flow_recall": (sum(recalls.values()) / len(recalls)) if recalls else None,
        "families_below_0_95": sorted(f for f, v in recalls.items() if v < 0.95),
        "lab_benign_fpr": (false_positives / negatives) if negatives else None,
        "negatives": negatives,
        "per_family": {f: round(v, 4) for f, v in sorted(recalls.items())},
    }


def compare(lab_csv: Path, qc_json: Path, *, max_lab_fpr: float = 0.01,
            salt: str = "full68-route-v1") -> dict[str, Any]:
    rows, _ = keep_scorable(load(lab_csv))
    tls_by_session = opening_is_tls(json.loads(qc_json.read_text()))
    # Positives the router sends to the TCP branch, plus every benign row as the
    # shared negative class. Both candidates are judged on this one population.
    tcp_rows = [row for row in rows
                if str(row.get("y")) != "1" or row_route(row) == "tcp_tls_fast"]
    split = build_split(with_capture_cells(tcp_rows), CAPTURE_CELL, ROLES,
                        salt=salt, stratify_key="label_family")
    train_rows = rows_for_role(tcp_rows, split, "train")
    validation_rows = rows_for_role(tcp_rows, split, "validation")
    test_rows = rows_for_role(tcp_rows, split, "test")

    result: dict[str, Any] = {
        "rows": {"train": len(train_rows), "validation": len(validation_rows), "test": len(test_rows)},
        "max_lab_fpr_budget": max_lab_fpr,
        "tls_opening_sessions": sum(1 for value in tls_by_session.values() if value),
        "non_tls_opening_sessions": sum(1 for value in tls_by_session.values() if not value),
    }

    # --- candidate A: one model for all TCP --------------------------------
    model = _fit(train_rows)
    negatives = [row for row in validation_rows if str(row.get("y")) != "1"]
    threshold = threshold_for_fpr(_scores(model, negatives), max_lab_fpr)
    if model is None or threshold is None:
        result["three_routes"] = {"status": "no_operating_point"}
    else:
        scores = _scores(model, test_rows)
        result["three_routes"] = _evaluate(
            [(row, value >= threshold) for row, value in zip(test_rows, scores)]
        )
        result["three_routes"]["threshold"] = threshold

    # --- candidate B: TCP split by the app-layer opening --------------------
    arms: dict[str, dict[str, Any]] = {}
    decided: list[tuple[dict[str, Any], bool]] = []
    ok = True
    for arm in ("tls", "opaque"):
        arm_train = [row for row in train_rows
                     if str(row.get("y")) != "1" or arm_of(row, tls_by_session) == arm]
        arm_validation = [row for row in validation_rows
                          if str(row.get("y")) != "1" or arm_of(row, tls_by_session) == arm]
        arm_test = [row for row in test_rows if arm_of(row, tls_by_session) == arm]
        arm_model = _fit(arm_train)
        arm_negatives = [row for row in arm_validation if str(row.get("y")) != "1"]
        arm_threshold = threshold_for_fpr(_scores(arm_model, arm_negatives), max_lab_fpr)
        positives = sum(1 for row in arm_train if str(row.get("y")) == "1")
        arms[arm] = {"train_positives": positives, "test_rows": len(arm_test),
                     "threshold": arm_threshold}
        if arm_model is None or arm_threshold is None:
            ok = False
            continue
        scores = _scores(arm_model, arm_test)
        decided.extend((row, value >= arm_threshold) for row, value in zip(arm_test, scores))
    result["four_routes"] = ({"status": "no_operating_point", "arms": arms} if not ok
                             else {**_evaluate(decided), "arms": arms})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-csv", required=True, type=Path)
    parser.add_argument("--qc-json", required=True, type=Path)
    parser.add_argument("--max-lab-fpr", type=float, default=0.01)
    parser.add_argument("--out-json", type=Path, default=None)
    args = parser.parse_args()
    result = compare(args.lab_csv, args.qc_json, max_lab_fpr=args.max_lab_fpr)
    if args.out_json:
        args.out_json.write_text(json.dumps(result, indent=2) + "\n")
    summary = {
        key: {metric: result[key].get(metric) for metric in
              ("worst_family_flow_recall", "mean_family_flow_recall", "lab_benign_fpr", "families")}
        for key in ("three_routes", "four_routes") if isinstance(result.get(key), dict)
    }
    print(json.dumps({"rows": result["rows"], "summary": summary,
                      "below_0_95": {k: result[k].get("families_below_0_95")
                                     for k in ("three_routes", "four_routes")
                                     if isinstance(result.get(k), dict)}},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
