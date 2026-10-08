#!/usr/bin/env python3
"""Look for the ways this corpus could be separable for the wrong reason.

Every check here is designed to FAIL on a corpus that flatters the model:

* roles that share a session, so the same capture trains and tests;
* a benign twin whose paired tunnel session sits in another role — the twin is
  captured from the same cell on purpose, so its role must follow its tunnel's
  or the negative in test is a near-copy of something seen in training;
* a single feature that already separates the classes, which means the model
  needs nothing else and the metric measures that feature, not the tunnel;
* a model trained on transport alone scoring well, which is the `is_udp`
  shortcut in general form;
* labels shuffled: anything above chance there is leakage through the split
  itself rather than through a feature.

It reports numbers, not a verdict. A shortcut is not automatically a defect —
`is_udp` really does separate WireGuard from HTTPS — but a shortcut nobody
named is how a lab result stops predicting the office.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from lab_pipeline.online_schema import FEATURE_NAMES
from lab_pipeline.split_manifest import build_split, rows_for_role
from lab_pipeline.train_fastv1 import keep_scorable, load, matrix
from lab_pipeline.train_route_lab import (
    CAPTURE_CELL,
    ROLES,
    capture_cell,
    row_route,
    with_capture_cells,
)

TRANSPORT_ONLY = ("is_tcp", "is_udp", "syn_count", "fin_count", "rst_count")


def twin_session(session_id: str) -> str | None:
    """The tunnel session a benign twin was captured beside, if it is one."""
    if session_id.endswith("_benign"):
        return session_id[: -len("_benign")] + "_tunnel"
    return None


def _group_key_of(split: dict) -> str:
    return str(split.get("group_key") or "session_id")


def role_of(split: dict, session_id: str) -> str | None:
    for role in ROLES:
        if session_id in set(split.get("groups", split.get("roles", {})).get(role, [])):
            return role
    return None


def check_group_disjoint(split: dict) -> dict[str, Any]:
    groups = split.get("groups", split.get("roles", {}))
    seen: dict[str, str] = {}
    overlaps: list[str] = []
    for role in ROLES:
        for session in groups.get(role, []):
            if session in seen:
                overlaps.append(session)
            seen[session] = role
    return {"sessions": len(seen), "sessions_in_two_roles": sorted(set(overlaps))[:20],
            "ok": not overlaps}


def check_twin_roles(split: dict) -> dict[str, Any]:
    """A benign twin must share its tunnel's role, or test negatives are
    near-copies of training material.

    When the split is grouped by capture cell the pair shares a group by
    construction and there is nothing left to check, so the cell itself is
    expanded back into its two sessions to keep the check meaningful.
    """
    groups = split.get("groups", split.get("roles", {}))
    if _group_key_of(split) == CAPTURE_CELL:
        role_by_session = {
            f"{cell}{suffix}": role
            for role in ROLES for cell in groups.get(role, [])
            for suffix in ("_tunnel", "_benign")
        }
    else:
        role_by_session = {s: role for role in ROLES for s in groups.get(role, [])}
    paired = 0
    split_pairs: list[tuple[str, str, str]] = []
    for session, role in role_by_session.items():
        tunnel = twin_session(session)
        if tunnel is None or tunnel not in role_by_session:
            continue
        paired += 1
        if role_by_session[tunnel] != role:
            split_pairs.append((session, role, role_by_session[tunnel]))
    return {
        "twin_pairs_present": paired,
        "twin_pairs_in_different_roles": len(split_pairs),
        "examples": [{"benign_role": b, "tunnel_role": t} for _, b, t in split_pairs[:5]],
        "ok": not split_pairs,
    }


def _balanced_accuracy(values: list[float], labels: list[int], threshold: float) -> float:
    positives = sum(labels) or 1
    negatives = len(labels) - sum(labels) or 1
    true_positive = sum(1 for v, y in zip(values, labels) if y == 1 and v >= threshold)
    false_positive = sum(1 for v, y in zip(values, labels) if y == 0 and v >= threshold)
    return 0.5 * (true_positive / positives + 1 - false_positive / negatives)


def single_feature_shortcuts(rows: list[dict[str, Any]], top_n: int = 10) -> list[dict[str, Any]]:
    """Best balanced accuracy any ONE feature reaches with one threshold."""
    labels = [1 if str(row.get("y")) == "1" else 0 for row in rows]
    if not labels or len(set(labels)) < 2:
        return []
    out: list[dict[str, Any]] = []
    for index, name in enumerate(FEATURE_NAMES):
        values = [float(row.get(name) or 0.0) for row in rows]
        candidates = sorted({round(v, 6) for v in values})
        if len(candidates) > 64:
            step = len(candidates) / 64
            candidates = [candidates[int(i * step)] for i in range(64)]
        best = max(
            (_balanced_accuracy(values, labels, t), t) for t in candidates
        ) if candidates else (0.0, 0.0)
        direction = "high=tunnel"
        # The mirror threshold: a feature that is LOW for tunnels separates just
        # as well, and reporting only one direction would hide half the shortcuts.
        worst = min((_balanced_accuracy(values, labels, t), t) for t in candidates)
        if 1 - worst[0] > best[0]:
            best = (1 - worst[0], worst[1])
            direction = "low=tunnel"
        out.append({"feature": name, "balanced_accuracy": round(best[0], 4),
                    "threshold": best[1], "direction": direction})
    out.sort(key=lambda entry: -entry["balanced_accuracy"])
    return out[:top_n]


def _fit_score(train_rows, test_rows, feature_names, *, shuffle_labels=False, seed=42):
    from sklearn.ensemble import RandomForestClassifier

    def sub(rows):
        return [[float(row.get(name) or 0.0) for name in feature_names] for row in rows], \
               [1 if str(row.get("y")) == "1" else 0 for row in rows]

    x_train, y_train = sub(train_rows)
    x_test, y_test = sub(test_rows)
    if shuffle_labels:
        rng = random.Random(seed)
        y_train = y_train[:]
        rng.shuffle(y_train)
    if len(set(y_train)) < 2 or len(set(y_test)) < 2:
        return None
    model = RandomForestClassifier(n_estimators=120, max_depth=12, min_samples_leaf=5,
                                   class_weight="balanced_subsample", n_jobs=2, random_state=seed)
    model.fit(x_train, y_train)
    scores = [float(p[1]) for p in model.predict_proba(x_test)]
    # AUC without sklearn.metrics so this stays importable anywhere.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks: dict[int, float] = {}
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        mean_rank = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = mean_rank
        i = j + 1
    positives = [ranks[i] for i, y in enumerate(y_test) if y == 1]
    n_pos, n_neg = len(positives), len(y_test) - len(positives)
    if not n_pos or not n_neg:
        return None
    auc = (sum(positives) - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
    return round(auc, 4)


def audit(csv_path: Path, route: str | None = None, salt: str = "full68-route-v1") -> dict[str, Any]:
    rows, _ = keep_scorable(load(csv_path))
    if route:
        rows = [row for row in rows if str(row.get("y")) != "1" or row_route(row) == route]
    split = build_split(with_capture_cells(rows), CAPTURE_CELL, ROLES,
                        salt=salt, stratify_key="label_family")
    train_rows = rows_for_role(rows, split, "train")
    test_rows = rows_for_role(rows, split, "test")
    result: dict[str, Any] = {
        "route": route or "all",
        "rows": {"total": len(rows), "train": len(train_rows), "test": len(test_rows)},
        "positives": sum(1 for row in rows if str(row.get("y")) == "1"),
        "group_disjoint": check_group_disjoint(split),
        "twin_roles": check_twin_roles(split),
        "single_feature_shortcuts": single_feature_shortcuts(train_rows),
    }
    try:
        result["auc_all_features"] = _fit_score(train_rows, test_rows, FEATURE_NAMES)
        result["auc_transport_only"] = _fit_score(train_rows, test_rows, TRANSPORT_ONLY)
        result["auc_shuffled_labels"] = _fit_score(train_rows, test_rows, FEATURE_NAMES,
                                                   shuffle_labels=True)
    except ImportError:
        result["auc_all_features"] = None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-csv", required=True, type=Path)
    parser.add_argument("--route", default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--salt", default="full68-route-v1")
    args = parser.parse_args()
    result = audit(args.lab_csv, args.route, args.salt)
    if args.out_json:
        args.out_json.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
