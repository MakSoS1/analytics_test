#!/usr/bin/env python3
"""Train ONE lab-phase route model from lab captures only.

This is deliberately not `train_fastv1.py`. That trainer selects its operating
point on office negatives, which is the right thing for a production candidate
and the wrong thing here: the office phase is separate and has not run. So this
one picks its threshold on the lab benign twins and stamps the result as such,
which makes it impossible to mistake the number for an office-calibrated one.

The route split is what makes four models instead of one honest: a QUIC family
and a TLS family do not share a decision surface, and averaging them hides both.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from lab_pipeline.flow_tier import export_forest
from lab_pipeline.full_scope import ROUTES, load_full_scope
from lab_pipeline.route_contract import ROUTES as ROUTE_NAMES, classify_route, route_spec
from lab_pipeline.model_bundle import stamp_contract
from lab_pipeline.online_schema import FEATURE_NAMES
from lab_pipeline.split_manifest import build_split, rows_for_role, verify_disjoint
from lab_pipeline.train_fastv1 import (
    InsufficientSplitGroups,
    code_sha256,
    keep_scorable,
    load,
    matrix,
    threshold_for_fpr,
)


ROLES = {"train": 0.5, "validation": 0.25, "test": 0.25}
THRESHOLD_SOURCE = "lab_benign_twins"

# Only the forest can be exported. `flow_tier.export_forest` / `predict_proba`
# are a tree-averaging pair that the sensor reproduces bit for bit in float32;
# a boosted model sums leaf values in log-odds and needs its own evaluator, so
# emitting one here would produce a file the sensor cannot score. The other
# learners exist to answer "is a different algorithm worth that work", and they
# write a report without a model.
EXPORTABLE_LEARNERS = frozenset({"rf"})
LEARNERS = ("rf", "hist_gbdt", "lightgbm")


def build_classifier(learner: str, args: argparse.Namespace):
    """Return an unfitted estimator for the requested learner."""
    if learner == "rf":
        from sklearn.ensemble import RandomForestClassifier

        return RandomForestClassifier(
            n_estimators=args.trees, max_depth=args.max_depth,
            min_samples_leaf=args.min_samples_leaf,
            class_weight=None if args.family_balance else "balanced_subsample",
            n_jobs=args.n_jobs, random_state=42,
        )
    if learner == "hist_gbdt":
        from sklearn.ensemble import HistGradientBoostingClassifier

        return HistGradientBoostingClassifier(
            max_iter=args.trees, max_depth=args.max_depth,
            min_samples_leaf=args.min_samples_leaf,
            class_weight=None if args.family_balance else "balanced",
            early_stopping=True, random_state=42,
        )
    if learner == "lightgbm":
        from lightgbm import LGBMClassifier

        return LGBMClassifier(
            n_estimators=args.trees, max_depth=args.max_depth,
            min_child_samples=args.min_samples_leaf,
            class_weight=None if args.family_balance else "balanced",
            n_jobs=args.n_jobs, random_state=42, verbose=-1,
        )
    raise ValueError(f"unknown learner {learner!r}")


def family_sample_weights(rows: list[dict[str, Any]]) -> list[float]:
    """Give every family the same total influence, and benign the same as all
    tunnels together.

    `class_weight="balanced_subsample"` balances tunnel against benign and
    nothing else, so a family that yields many flows per session outvotes a
    family that yields one — while the release gate is a floor on EVERY
    family's recall. These weights make the objective match the gate.
    """
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        key = str(row.get("label_family") or "") if str(row.get("y")) == "1" else "__benign__"
        counts[key] += 1
    families = [key for key in counts if key != "__benign__"]
    if not families:
        return [1.0] * len(rows)
    weights: dict[str, float] = {
        family: 1.0 / (len(families) * counts[family]) for family in families
    }
    if counts.get("__benign__"):
        weights["__benign__"] = 1.0 / counts["__benign__"]
    scale = len(rows)
    return [
        weights[str(row.get("label_family") or "") if str(row.get("y")) == "1" else "__benign__"] * scale
        for row in rows
    ]


def route_of_family(scope: dict) -> dict[str, str]:
    """The route each family is DECLARED under in the catalogue.

    Kept for reporting the gap against `row_route`, which is what the sensor
    actually does. It must never again decide what a model trains on.
    """
    return {row["family"]: row["route"] for row in scope["families"]}


CAPTURE_CELL = "capture_cell"


def capture_cell(session_id: str) -> str:
    """The campaign cell a session belongs to, with its mode removed.

    A benign twin is captured from the SAME cell as its tunnel — same lane,
    workload, network profile, duration and sink objects — so splitting by
    session put 496 of 801 pairs on opposite sides: the negative in test was a
    near-copy of a capture that had trained the model. Grouping by the cell
    keeps a pair together without merging unrelated sessions.
    """
    for suffix in ("_tunnel", "_benign"):
        if session_id.endswith(suffix):
            return session_id[: -len(suffix)]
    return session_id


def with_capture_cells(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach the split group in place and return the same rows."""
    for row in rows:
        row[CAPTURE_CELL] = capture_cell(str(row.get("session_id") or ""))
    return rows


def row_route(row: dict[str, Any]) -> str:
    """The route the RUNTIME router assigns this flow.

    Never the family's declared route. `classify_route` sends every TCP flow to
    tcp_tls_fast and every UDP flow to quic_udp; it has no family label and
    cannot get one. Training by the declared route put every TCP family that the
    catalogue calls opaque_outer into a model the router never sends TCP to,
    while the model that actually scores them had never seen them as positives.
    """
    recorded = str(row.get("router_route") or "")
    if recorded in ROUTE_NAMES:
        return recorded
    # Feature tables written before router_route existed: fall back to the same
    # function on whatever transport the row does carry.
    if str(row.get("is_tcp")) in {"1", "1.0", "True"}:
        proto = "tcp"
    elif str(row.get("is_udp")) in {"1", "1.0", "True"}:
        proto = "udp"
    else:
        proto = ""
    return classify_route({"proto": proto})


def select_route_rows(
    rows: list[dict[str, Any]], route: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Tunnel rows the router sends here, plus every benign row as the negative.

    Benign rows are shared across routes on purpose: the negative a route model
    must not fire on is ordinary traffic, not "ordinary traffic that happens to
    be the same transport as this route".
    """
    kept: list[dict[str, Any]] = []
    families: set[str] = set()
    for row in rows:
        if str(row.get("y")) == "1":
            if row_route(row) != route:
                continue
            families.add(str(row.get("label_family") or ""))
        kept.append(row)
    return kept, sorted(families)


def observed_routing(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Where the router actually sends each family's flows.

    A family may legitimately split — a tunnel with a UDP data plane and a TCP
    control plane produces both — so a split is reported as a fact about the
    family rather than resolved behind the reader's back.
    """
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        if str(row.get("y")) != "1":
            continue
        out[str(row.get("label_family") or "")][row_route(row)] += 1
    return {family: dict(sorted(counts.items())) for family, counts in sorted(out.items())}


def feature_importances(classifier: Any, top_n: int = 25) -> list[dict[str, Any]]:
    """The forest's own impurity-based importances, taken from the fitted model.

    Not recomputed from the exported JSON: `export_forest` keeps only the split
    feature, threshold and leaf probability, so a node-count proxy calculated
    there would be a different quantity wearing the same name.
    """
    raw = getattr(classifier, "feature_importances_", None)
    if raw is None:
        return []
    total = float(sum(float(value) for value in raw)) or 1.0
    # LightGBM reports split counts, sklearn reports normalised impurity gain;
    # normalising here keeps the column comparable between learners.
    ranked = [
        {"name": name, "importance": float(value) / total}
        for name, value in zip(FEATURE_NAMES, raw)
        if float(value) > 0
    ]
    ranked.sort(key=lambda row: (-row["importance"], row["name"]))
    return ranked[:top_n]


def per_family_recall(
    model_scores: list[float], rows: list[dict[str, Any]], threshold: float,
) -> dict[str, dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = {}
    for score, row in zip(model_scores, rows):
        if str(row.get("y")) != "1":
            continue
        family = str(row.get("label_family") or "")
        slot = stats.setdefault(family, {"rows": 0, "flagged": 0})
        slot["rows"] += 1
        slot["flagged"] += int(score >= threshold)
    for slot in stats.values():
        slot["flow_recall"] = slot["flagged"] / slot["rows"] if slot["rows"] else 0.0
    return dict(sorted(stats.items()))


def _report(args, classifier, threshold, families, train_rows, validation_rows,
            test_rows, score, *, exported: bool) -> dict:
    """The same numbers for every learner, so the comparison is like for like."""
    test_scores = score(test_rows)
    negatives = [value for value, row in zip(test_scores, test_rows) if str(row.get("y")) != "1"]
    per_family = per_family_recall(test_scores, test_rows, threshold)
    return {
        "status": "ok",
        "phase": "lab",
        "route": args.route,
        "learner": args.learner,
        "family_balanced": bool(args.family_balance),
        "exportable": exported,
        "threshold": threshold,
        "threshold_source": THRESHOLD_SOURCE,
        "office_calibrated": False,
        "families": families,
        "rows": {
            "train": len(train_rows), "validation": len(validation_rows), "test": len(test_rows),
        },
        "lab_benign_fpr_test": (
            sum(1 for value in negatives if value >= threshold) / len(negatives)
            if negatives else None
        ),
        # The release gate is a floor on the WORST family, so that is the headline
        # number; a mean would let a strong family carry a failing one.
        "worst_family_flow_recall": min(
            (stats["flow_recall"] for stats in per_family.values()), default=None,
        ),
        "families_below_0_95": sorted(
            family for family, stats in per_family.items() if stats["flow_recall"] < 0.95
        ),
        "per_family": per_family,
        "observed_routing": observed_routing(train_rows + validation_rows + test_rows),
        "feature_importances": feature_importances(classifier),
        "code_sha256": code_sha256(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-csv", required=True)
    parser.add_argument("--route", required=True, choices=sorted(ROUTES))
    parser.add_argument("--out-model", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--max-lab-fpr", type=float, default=0.01,
                        help="operating point on the LAB benign twins, not on office traffic")
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=16)
    parser.add_argument("--min-samples-leaf", type=int, default=5)
    parser.add_argument("--n-jobs", type=int, default=2)
    parser.add_argument("--salt", default="full68-route-v1")
    parser.add_argument("--learner", default="rf", choices=LEARNERS,
                        help="rf is the only exportable learner; the others report only")
    parser.add_argument("--family-balance", action="store_true",
                        help="weight every family equally instead of only balancing the two classes")
    args = parser.parse_args()

    all_rows, _ = keep_scorable(load(Path(args.lab_csv)))
    rows, families = select_route_rows(all_rows, args.route)
    if not families:
        # An unreachable route is a design answer, not a training failure, so
        # say where the router does send this corpus's tunnel flows.
        print(json.dumps({
            "status": "no_families_for_route",
            "route": args.route,
            "note": "the runtime router sends no tunnel flow in this corpus to this route",
            "observed_routes": {
                name: sum(1 for row in all_rows
                          if str(row.get("y")) == "1" and row_route(row) == name)
                for name in ROUTE_NAMES
            },
        }, sort_keys=True))
        return 3

    try:
        split = build_split(with_capture_cells(rows), CAPTURE_CELL, ROLES,
                            salt=args.salt, stratify_key="label_family")
        verify_disjoint(split)
    except InsufficientSplitGroups as exc:
        print(json.dumps({
            "status": "insufficient_split_groups", "route": args.route, "detail": str(exc),
        }))
        return 3

    train_rows = rows_for_role(rows, split, "train")
    validation_rows = rows_for_role(rows, split, "validation")
    test_rows = rows_for_role(rows, split, "test")
    x_train, y_train = matrix(train_rows)
    if len(set(y_train)) < 2:
        print(json.dumps({"status": "single_class_train", "route": args.route}))
        return 4

    classifier = build_classifier(args.learner, args)
    if args.family_balance:
        classifier.fit(x_train, y_train, sample_weight=family_sample_weights(train_rows))
    else:
        classifier.fit(x_train, y_train)

    def score(rows_in: list[dict[str, Any]]) -> list[float]:
        if not rows_in:
            return []
        matrix_in, _ = matrix(rows_in)
        return [float(value[1]) for value in classifier.predict_proba(matrix_in)]

    negatives = [row for row in validation_rows if str(row.get("y")) != "1"]
    threshold = threshold_for_fpr(score(negatives), args.max_lab_fpr)
    if threshold is None:
        print(json.dumps({
            "status": "no_feasible_operating_point", "route": args.route,
            "detail": "no threshold satisfies the lab benign FPR budget",
        }))
        return 5

    spec = route_spec(args.route)
    if args.learner not in EXPORTABLE_LEARNERS:
        # Report only. Writing a JSON forest here would be a file the sensor's
        # tree-averaging evaluator silently mis-scores.
        report = _report(args, classifier, threshold, families,
                         train_rows, validation_rows, test_rows, score, exported=False)
        Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": "ok", "route": args.route, "learner": args.learner,
            "exported": False, "threshold": threshold, "out_json": args.out_json,
            "note": "comparison run; no deployable model written for this learner",
        }))
        return 0
    model = export_forest(classifier, list(FEATURE_NAMES))
    if args.route == "tcp_tls_fast":
        # This route is loaded by ModelBundle, which demands the fast-v1 stamp.
        model = stamp_contract(model)
    else:
        # Every other route carries its own identity so a model can never be
        # loaded into a route it was not trained for.
        model["schema_version"] = spec.schema_version
        model["contract_hash"] = spec.contract_hash
    if list(model["features"]) != list(spec.features):
        raise SystemExit(f"{args.route}: trained feature order does not match the route contract")
    model["threshold"] = threshold
    # Anyone loading these bytes must be able to see that the operating point
    # was never calibrated against office traffic.
    model["phase"] = "lab"
    model["route"] = args.route
    model["threshold_source"] = THRESHOLD_SOURCE
    Path(args.out_model).write_text(json.dumps(model) + "\n", encoding="utf-8")

    report = _report(args, classifier, threshold, families,
                     train_rows, validation_rows, test_rows, score, exported=True)
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "ok", "route": args.route, "families": len(families),
        "threshold": threshold, "out_model": args.out_model, "out_json": args.out_json,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
