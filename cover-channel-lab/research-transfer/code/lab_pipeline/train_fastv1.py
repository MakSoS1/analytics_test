#!/usr/bin/env python3
"""Train the fast-v1 detector: contract-stamped, group-split, validation-thresholded.

The first trainer whose output `model_bundle` will accept in strict mode. Every
earlier model used the legacy 112-feature session schema, so the vector it scored
was not the vector the sensor produces.

What this enforces, each because the previous version got it wrong:

* **Group-disjoint splits.** Lab rows split by session; office rows held out by
  time, latest hours as test, through `split_manifest`. No row-position fallback
  — too few groups is an error, not a licence to cut the list in half.
* **Threshold from validation.** Chosen on office validation rows the forest
  never trained on, and never on the test slice.
* **Unscorable rows excluded on purpose.** Mid-stream joins and too-short flows
  are dropped explicitly and counted, not silently mixed into the negatives.
* **Per-family truth.** Reporting goes through `evaluate_alerts`, so a family at
  0.69 cannot hide behind a flow-weighted 0.998.
* **Contract stamped into the artifact.** Schema version and contract hash travel
  with the model; a sensor that computes anything else is refused at load.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
from lab_pipeline.evaluate_alerts import evaluate  # noqa: E402
from lab_pipeline.extract_fastv1_features import EXCLUSIONS_PATH  # noqa: E402
from lab_pipeline.flow_tier import export_forest  # noqa: E402
from lab_pipeline.model_bundle import stamp_contract  # noqa: E402
from lab_pipeline.online_schema import FEATURE_NAMES  # noqa: E402
from lab_pipeline.supported_tunnels import declared_families  # noqa: E402
from lab_pipeline.split_manifest import (  # noqa: E402
    MIN_GROUPS_PER_ROLE,
    InsufficientSplitGroups,
    build_split,
    rows_for_role,
    verify_disjoint,
)

ROLES = {"train": 0.5, "validation": 0.25, "test": 0.25}


def code_sha256() -> str:
    """Identify this package without Git: SHA256 of the lab_pipeline sources."""
    root = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for path in sorted(root.glob("*.py")):
        h.update(path.name.encode("utf-8") + b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metadata_session_counts(*dirs: str | None) -> dict[str, int] | None:
    counts: dict[str, int] = defaultdict(int)
    found = False
    for raw in dirs:
        if not raw:
            continue
        root = Path(raw)
        if not root.is_dir():
            continue
        for f in root.glob("*_tunnel.json"):
            try:
                d = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            found = True
            counts[str(d.get("label_family") or "?")] += 1
    return dict(counts) if found else None


def capture_id_ts(capture_id: str) -> str:
    """YYYYMMDDTHHMMSS prefix. The hyphenated window suffix is not part of time.

    `20260914T200244-1227` > `20260914T200244` as a raw string, so comparing the
    full capture_id to a freeze timestamp would drop the cut window itself.
    """
    return (capture_id or "").split("-", 1)[0]


def exclude_office_after(
    rows: list[dict[str, Any]], after_ts: str | None,
) -> tuple[list[dict[str, Any]], int]:
    """Drop capture windows whose timestamp is strictly after `after_ts`."""
    if not after_ts:
        return list(rows), 0
    kept: list[dict[str, Any]] = []
    n = 0
    for r in rows:
        if capture_id_ts(str(r.get("capture_id") or "")) > after_ts:
            n += 1
            continue
        kept.append(r)
    return kept, n


def take_rows_per_window(
    rows: list[dict[str, Any]], max_per_window: int | None,
) -> tuple[list[dict[str, Any]], int]:
    """Uniform per-window cap. None keeps every row.

    Capping train/val while leaving weekday test uncapped is how run3 picked a
    night-time threshold and then failed on weekday density.
    """
    if max_per_window is None:
        return list(rows), 0
    counts: dict[str, int] = {}
    kept: list[dict[str, Any]] = []
    dropped = 0
    for r in rows:
        cid = str(r.get("capture_id") or "")
        n = counts.get(cid, 0)
        if n >= max_per_window:
            dropped += 1
            continue
        counts[cid] = n + 1
        kept.append(r)
    return kept, dropped


def office_split(
    office: list[dict[str, Any]],
    val_from: str | None = None,
    salt: str = "fastv1-v1",
) -> dict[str, Any]:
    """Chronological office split; optional weekday cut for validation.

    Default 50/25/25 on the whole file puts the last quarter — on this corpus,
    the weekday — entirely in test, so the threshold is chosen on night/morning
    validation. `val_from` keeps every earlier window in train and splits the
    remaining windows 50/50 into validation and test.
    """
    if not val_from:
        return build_split(office, "capture_id", ROLES, salt=salt,
                           chronological=True)
    groups = sorted({str(r.get("capture_id") or "") for r in office})
    missing = sum(1 for g in groups if not g)
    if missing:
        raise InsufficientSplitGroups(
            f"{missing} rows have no 'capture_id'; a row without a group cannot be placed"
        )
    train_g = [g for g in groups if capture_id_ts(g) < val_from]
    rest = [g for g in groups if capture_id_ts(g) >= val_from]
    mid = len(rest) // 2
    assigned = {
        "train": train_g,
        "validation": rest[:mid],
        "test": rest[mid:],
    }
    thin = {role: len(gs) for role, gs in assigned.items()
            if len(gs) < MIN_GROUPS_PER_ROLE}
    if thin:
        raise InsufficientSplitGroups(
            f"insufficient_split_groups: {thin} (need >= {MIN_GROUPS_PER_ROLE} per role; "
            f"{len(groups)} distinct groups available, val_from={val_from})"
        )
    member = {g: role for role, gs in assigned.items() for g in gs}
    counts: dict[str, int] = defaultdict(int)
    for r in office:
        counts[member[str(r.get("capture_id") or "")]] += 1
    return {
        "group_key": "capture_id",
        "stratify_key": None,
        "chronological": True,
        "salt": salt,
        "fractions": {"train": "before_val_from", "validation": 0.5, "test": 0.5},
        "groups": {role: list(gs) for role, gs in assigned.items()},
        "group_counts": {role: len(gs) for role, gs in assigned.items()},
        "row_counts": dict(counts),
        "distinct_groups": len(groups),
        "office_val_from": val_from,
    }


def load(path: Path) -> list[dict[str, Any]]:
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    with opener(path, "rt") as fh:
        return list(csv.DictReader(fh))


def load_office(
    path: Path,
    exclude_after: str | None = None,
    max_per_window: int | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    """Stream office rows, dropping the frozen holdout and applying a uniform cap.

    Dropped holdout rows are never materialised. That is the RAM difference
    between filtering after `load()` and not loading the evening slice at all.
    """
    opener: Any = open
    if path.suffix == ".gz":
        import gzip

        opener = gzip.open
    kept: list[dict[str, Any]] = []
    holdout = 0
    capped = 0
    counts: dict[str, int] = {}
    with opener(path, "rt") as fh:
        for r in csv.DictReader(fh):
            if exclude_after and capture_id_ts(str(r.get("capture_id") or "")) > exclude_after:
                holdout += 1
                continue
            cid = str(r.get("capture_id") or "")
            if max_per_window is not None:
                n = counts.get(cid, 0)
                if n >= max_per_window:
                    capped += 1
                    continue
                counts[cid] = n + 1
            kept.append(r)
    return kept, holdout, capped


def matrix(rows: list[dict[str, Any]]):
    x = [[float(r.get(f) or 0.0) for f in FEATURE_NAMES] for r in rows]
    y = [int(float(r.get("y") or 0)) for r in rows]
    return x, y


def keep_scorable(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    kept = [r for r in rows if str(r.get("scorable", "1")) == "1"]
    return kept, len(rows) - len(kept)


def threshold_for_fpr(neg_scores: list[float], max_fpr: float) -> float | None:
    """Lowest threshold whose false positive count fits the budget, or None.

    Scoring compares with `>=`, so the threshold has to land strictly above the
    score it is derived from. When that score is already at the top of the range
    there is no such value: `threshold_for_fpr([1.0] * 100, 1e-4)` used to clamp
    to 1.0 and then fire on all 100 negatives — a threshold computed from an FPR
    budget that delivered a 100% false positive rate. None means the budget and
    this score distribution have no operating point, which is a result the
    caller must handle, not round away.
    """
    if not neg_scores:
        return 0.5
    ordered = sorted(neg_scores, reverse=True)
    allowed = int(len(ordered) * max_fpr)
    if allowed >= len(ordered):
        return 0.0
    cut = ordered[allowed]
    thr = min(1.0, cut + 1e-9)
    if thr <= cut:
        return None
    return thr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab-csv", required=True, help="fast-v1 lab rows (extract_fastv1_features)")
    ap.add_argument("--office-csv", required=True, help="fast-v1 office rows (collect_office_fastv1)")
    ap.add_argument("--out-model", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--max-fpr", type=float, default=1e-4)
    ap.add_argument("--family-recall-floor", type=float, default=0.95)
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--min-samples-leaf", type=int, default=1,
                    help="minimum sklearn samples per leaf; values above 1 "
                         "regularise leaves that otherwise fit one lab example")
    ap.add_argument("--n-jobs", type=int, default=-1,
                    help="sklearn fit parallelism; 2 on the 11GiB lab host")
    ap.add_argument("--salt", default="fastv1-v1")
    ap.add_argument("--metadata-dir", default=None,
                    help="lab metadata; coverage denominator is sessions here, not CSV rows")
    ap.add_argument("--extra-metadata-dir", default=None,
                    help="second metadata tree whose sessions also belong in the denominator")
    ap.add_argument("--mix-csv", default=None,
                    help="labelled mix (y=0/1) for precision at the frozen threshold")
    ap.add_argument("--office-exclude-after", default=None,
                    help="drop office windows whose capture timestamp is strictly "
                         "after this YYYYMMDDTHHMMSS; the frozen evening holdout")
    ap.add_argument("--office-val-from", default=None,
                    help="windows with timestamp >= this go to val/test (50/50); "
                         "earlier windows train. Puts weekday morning into train.")
    ap.add_argument("--office-max-rows-per-window", type=int, default=None,
                    help="uniform per-window cap applied to every role")
    args = ap.parse_args()
    if args.min_samples_leaf < 1:
        ap.error("--min-samples-leaf must be at least 1")

    from sklearn.ensemble import RandomForestClassifier

    lab_all = load(Path(args.lab_csv))
    off_all, holdout_dropped, cap_dropped = load_office(
        Path(args.office_csv),
        exclude_after=args.office_exclude_after,
        max_per_window=args.office_max_rows_per_window,
    )
    lab, lab_dropped = keep_scorable(lab_all)
    office, off_dropped = keep_scorable(off_all)
    for r in office:
        r["y"] = 0

    try:
        # Stratify by family so no family falls under the 50-session floor
        # because of where the hash happened to put it.
        lab_split = build_split(lab, "session_id", ROLES, salt=args.salt,
                                stratify_key="label_family")
        # Office negatives get a TIME holdout, not a hashed one. Splitting by
        # capture window HASHED looked disjoint and was not: the same office
        # applications recur window after window, so the test slice was full of
        # connections whose siblings trained the model. That split reported 0
        # false positives over 5 788 rows while 30% of scorable flows alerted on
        # a capture taken from the same link four hours later, with every
        # alerting port already in the training data.
        #
        # The key is capture_id, ordered, not time_bucket: both sort
        # chronologically (capture_id begins with an ISO-8601 timestamp), but
        # hourly buckets accrue one group per hour, so a three-role split needs
        # six hours before it can be built at all. Capture windows give the same
        # forward-in-time guarantee at the granularity the collector actually
        # produces.
        #
        # Default 50/25/25 still fails when the last quarter is a weekday and
        # the middle quarter is night: threshold 0.21, then 220 weekday flags.
        # --office-val-from keeps the earlier windows (including weekday
        # morning) in train and splits the remainder 50/50.
        off_split = office_split(office, val_from=args.office_val_from,
                                 salt=args.salt)
        verify_disjoint(lab_split)
        verify_disjoint(off_split)
    except InsufficientSplitGroups as exc:
        print(json.dumps({
            "status": "insufficient_split_groups",
            "detail": str(exc),
            "note": "collect more sessions / capture windows; there is no row-tail fallback",
        }))
        return 3

    lab_tr = rows_for_role(lab, lab_split, "train")
    lab_va = rows_for_role(lab, lab_split, "validation")
    lab_te = rows_for_role(lab, lab_split, "test")
    off_tr = rows_for_role(office, off_split, "train")
    off_va = rows_for_role(office, off_split, "validation")
    off_te = rows_for_role(office, off_split, "test")

    xtr, ytr = matrix(lab_tr + off_tr)
    if len(set(ytr)) < 2:
        print(json.dumps({"status": "single_class_train", "note": "need both tunnel and benign rows"}))
        return 4

    clf = RandomForestClassifier(
        n_estimators=args.trees, max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        class_weight="balanced_subsample", n_jobs=args.n_jobs, random_state=42,
    )
    clf.fit(xtr, ytr)

    def proba(rows):
        if not rows:
            return []
        x, _ = matrix(rows)
        return [float(v[1]) for v in clf.predict_proba(x)]

    thr = threshold_for_fpr(proba(off_va), args.max_fpr)
    if thr is None:
        print(json.dumps({
            "status": "no_feasible_operating_point",
            "detail": f"no threshold satisfies max_fpr={args.max_fpr} on the office "
                      f"validation slice; its scores reach the top of the range",
            "office_validation_rows": len(off_va),
        }))
        return 5

    model = stamp_contract(export_forest(clf, list(FEATURE_NAMES)))
    model["threshold"] = thr
    Path(args.out_model).write_text(json.dumps(model) + "\n", encoding="utf-8")

    # The release list comes from the registry, not from whatever happens to be
    # in the corpus: a family that stopped being captured must fail the release
    # rather than quietly disappear from the report.
    report = evaluate(
        model, lab_te, off_te, thr,
        family_recall_floor=args.family_recall_floor, max_fpr=args.max_fpr,
        declared_families=declared_families(),
        metadata_sessions=_metadata_session_counts(
            args.metadata_dir, args.extra_metadata_dir),
        mix_rows=load(Path(args.mix_csv)) if args.mix_csv else None,
        test_manifest={
            "test_session_ids": list(lab_split["groups"]["test"]),
            "qc_excluded": [],
            "unscorable": [],
            "missing": [],
        },
    )
    report["split"] = {
        "lab_groups": lab_split["group_counts"], "lab_rows": lab_split["row_counts"],
        "office_groups": off_split["group_counts"], "office_rows": off_split["row_counts"],
        "office_split": (
            f"chronological; train = windows before {args.office_val_from}; "
            "remaining 50/50 val/test"
            if args.office_val_from else
            "chronological time holdout on capture_id (test = latest windows)"
        ),
        "office_val_from": args.office_val_from,
        "office_exclude_after": args.office_exclude_after,
        "office_test_buckets": [off_split["groups"]["test"][0], off_split["groups"]["test"][-1]]
        if off_split["groups"]["test"] else [],
        "lab_group_ids": lab_split["groups"],
        "office_group_ids": off_split["groups"],
        "salt": args.salt,
    }
    split_path = Path(str(args.out_model) + ".split.json")
    split_path.write_text(json.dumps({
        "group_key": "session_id",
        "salt": args.salt,
        "groups": lab_split["groups"],
        "group_counts": lab_split["group_counts"],
        "row_counts": lab_split["row_counts"],
        "lab_csv_sha256": _sha256(Path(args.lab_csv)),
        "office_csv_sha256": _sha256(Path(args.office_csv)),
        "code_sha256": code_sha256(),
    }, indent=2) + "\n", encoding="utf-8")
    report["excluded_unscorable"] = {"lab": lab_dropped, "office": off_dropped}
    report["excluded_office_holdout"] = holdout_dropped
    report["office_rows_dropped_per_window_cap"] = cap_dropped
    report["threshold_source"] = "office validation slice; test never used for the threshold"
    report["artifacts"] = {
        "model_sha256": _sha256(Path(args.out_model)),
        "lab_csv_sha256": _sha256(Path(args.lab_csv)),
        "office_csv_sha256": _sha256(Path(args.office_csv)),
        "exclusions_sha256": _sha256(EXCLUSIONS_PATH),
        "split_manifest_sha256": _sha256(split_path),
        "code_sha256": code_sha256(),
    }
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "threshold": thr,
        "micro_recall": round(report["micro_recall"], 4),
        "macro_recall": round(report["macro_recall"], 4),
        "families_below_floor": report["families_below_floor"],
        "office_fpr": report.get("office", {}).get("fpr"),
        "production_ready": report["production_ready"],
        "model": args.out_model,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
