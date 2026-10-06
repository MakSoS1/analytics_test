#!/usr/bin/env python3
"""Release evaluation of a FROZEN model: no retraining, no re-splitting.

The acceptance runner trains, splits and evaluates in one pass, which is right
for development and wrong for a release decision: run it again tomorrow on a
corpus that has grown, and it silently produces a different candidate. The
release question is the opposite one — "is THIS file good enough" — so this
module takes the model file as an immutable input and refuses to touch it.

What it guarantees:

* the artifact is loaded strictly (``ModelBundle``), exactly as a sensor would;
* the lab test slice is reproduced with the trainer's own deterministic split
  (same group key, same roles, same salt) — never re-drawn, never re-rolled;
* the office rows are scored as one untouched holdout: whatever capture
  windows the caller passes in, presumed negative, no y column invented;
* the labelled mix, if given, is scored at the model's own threshold;
* the report binds SHA256 of every input file, so the release card can check
  that the model it judges is the model this report measured.
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

from lab_pipeline.corpus_merge import keep_new_session_rows  # noqa: E402
from lab_pipeline.evaluate_alerts import evaluate  # noqa: E402
from lab_pipeline.extract_fastv1_features import EXCLUSIONS_PATH  # noqa: E402
from lab_pipeline.full_scope import load_full_scope, required_families  # noqa: E402
from lab_pipeline.model_bundle import ModelBundle  # noqa: E402
from lab_pipeline.split_manifest import (  # noqa: E402
    build_split,
    rows_for_role,
    verify_disjoint,
)
from lab_pipeline.supported_tunnels import declared_families  # noqa: E402
from lab_pipeline.train_fastv1 import ROLES, code_sha256, keep_scorable, load  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merge_extra(main_rows: list[dict[str, Any]],
                extra_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Append extra rows whose session_id is not already present (corpus_merge's rule)."""
    kept, dropped = keep_new_session_rows(main_rows, extra_rows)
    return list(main_rows) + kept, dropped


def _office_holdout_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups = sorted({str(r.get("capture_id") or "") for r in rows})
    return {
        "rows": len(rows),
        "capture_groups": len(groups),
        "first_capture": groups[0] if groups else None,
        "last_capture": groups[-1] if groups else None,
    }


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="frozen model artifact; never modified")
    ap.add_argument("--lab-csv", required=True)
    ap.add_argument("--lab-extra-csv", default=None,
                    help="second lab table, merged by session_id without double-counting")
    ap.add_argument("--office-csv", default=None, help="fresh office holdout rows")
    ap.add_argument("--holdout-note", default=None,
                    help="how the holdout was cut (e.g. windows collected after training)")
    ap.add_argument("--metadata-dir", default=None)
    ap.add_argument("--extra-metadata-dir", default=None)
    ap.add_argument("--mix-csv", default=None)
    ap.add_argument("--mix-recipe-json", default=None)
    ap.add_argument("--salt", default="fastv1-v1")
    ap.add_argument("--split-manifest", default=None,
                    help="frozen train/val/test groups written at training; "
                         "required to stop a grown corpus silently re-splitting")
    ap.add_argument("--scope", default=None,
                    help="canonical full-scope catalogue; requires --split-manifest")
    ap.add_argument("--phase", choices=("lab", "office"), default="office")
    ap.add_argument("--max-fpr", type=float, default=1e-4)
    ap.add_argument("--family-recall-floor", type=float, default=0.95)
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    if args.phase == "lab" and args.office_csv:
        print(json.dumps({"status": "lab_phase_refuses_office_input"}))
        return 4
    full_scope = load_full_scope(Path(args.scope)) if args.scope else None
    full_required = required_families(full_scope) if full_scope else []
    if full_scope and not args.split_manifest:
        print(json.dumps({"status": "full_scope_requires_frozen_manifest",
                          "detail": "full-scope evaluation cannot rebuild a split from a grown corpus"}))
        return 5

    model_path = Path(args.model)
    try:
        bundle = ModelBundle.load(model_path)
    except RuntimeError as exc:
        print(json.dumps({"status": "model_refused", "detail": str(exc)}))
        return 2
    thr = bundle.threshold

    lab = load(Path(args.lab_csv))
    extra_dropped: list[str] = []
    if args.lab_extra_csv:
        extra = load(Path(args.lab_extra_csv))
        lab, extra_dropped = merge_extra(lab, extra)
    lab, lab_dropped = keep_scorable(lab)

    test_manifest = None
    if args.split_manifest:
        man = json.loads(Path(args.split_manifest).read_text())
        expected = man.get("lab_csv_sha256") or man.get("source_sha256")
        actual = _sha256(Path(args.lab_csv))
        if expected and expected != actual:
            print(json.dumps({
                "status": "frozen_dataset_mismatch",
                "detail": "lab CSV SHA256 is not the hash frozen at training",
                "expected": expected,
                "actual": actual,
            }))
            return 5
        groups = man.get("groups") or (man.get("lab_group_ids") or {})
        if not groups.get("test"):
            print(json.dumps({"status": "split_manifest_missing_test"}))
            return 5
        lab_split = {
            "group_key": man.get("group_key") or "session_id",
            "groups": groups,
            "group_counts": {r: len(g) for r, g in groups.items()},
            "row_counts": man.get("row_counts") or {},
            "salt": man.get("salt") or args.salt,
        }
        test_manifest = {
            "test_session_ids": list(groups["test"]),
            "qc_excluded": list(man.get("qc_excluded") or []),
            "unscorable": list(man.get("unscorable") or []),
            "missing": list(man.get("missing") or []),
        }
    else:
        # Development path only. A release decision must pass --split-manifest.
        lab_split = build_split(lab, "session_id", ROLES, salt=args.salt,
                                stratify_key="label_family")
    verify_disjoint(lab_split)
    lab_test = rows_for_role(lab, lab_split, "test")
    if not lab_test:
        print(json.dumps({"status": "empty_test_slice"}))
        return 3

    office = None
    off_dropped = 0
    if args.office_csv:
        office, off_dropped = keep_scorable(load(Path(args.office_csv)))
        if not office:
            print(json.dumps({"status": "empty_office_holdout"}))
            return 3

    mix_rows = None
    if args.mix_csv:
        mix_rows = load(Path(args.mix_csv))
        bad = [r for r in mix_rows if str(r.get("y")) not in ("0", "1")]
        if bad:
            print(json.dumps({"status": "mix_rows_unlabelled",
                              "detail": f"{len(bad)} rows without y in (0,1)"}))
            return 4

    report = evaluate(
        bundle.model, lab_test, office, thr,
        family_recall_floor=args.family_recall_floor, max_fpr=args.max_fpr,
        metadata_sessions=_metadata_session_counts(args.metadata_dir,
                                                   args.extra_metadata_dir),
        declared_families=full_required or declared_families(),
        mix_rows=mix_rows,
        test_manifest=test_manifest,
    )
    report["evaluation_mode"] = "frozen_model_no_retraining"
    report["phase"] = args.phase
    if full_scope:
        report["full_scope"] = {
            "scope_version": full_scope.get("scope_version"),
            "required_families": full_required,
        }
    report["frozen_model"] = {
        "model_id": bundle.model_id,
        "source": str(model_path),
        "threshold": thr,
        "threshold_source": "the artifact's own, chosen on office validation before freezing",
        "n_trees": len(bundle.model.get("trees") or []),
    }
    frozen_manifest = bool(args.split_manifest)
    report["split"] = {
        "lab_split": (
            "frozen training split-manifest"
            if frozen_manifest else
            "rebuilt from salt; not a frozen release test"
        ),
        "salt": args.salt,
        "lab_groups": lab_split["group_counts"],
        "lab_row_counts": lab_split["row_counts"],
        "lab_group_ids": lab_split["groups"],
        "evaluated_slice": "test",
        "frozen_manifest": frozen_manifest,
    }
    report.setdefault("gates", {})["frozen_split_manifest"] = frozen_manifest
    if full_scope:
        report["gates"]["full_scope_frozen_manifest"] = frozen_manifest
    if not frozen_manifest:
        # A salt rebuild on a grown table is development. It must not clear
        # the release bit that evaluate() computed from the slice metrics.
        report["production_ready"] = False
    report["excluded_unscorable"] = {"lab": lab_dropped, "office": off_dropped}
    if extra_dropped:
        report["merge"] = {"dropped_duplicate_sessions": len(extra_dropped),
                           "detail": extra_dropped[:10]}
    if office is not None:
        report["office_holdout"] = _office_holdout_summary(office)
        if args.holdout_note:
            report["office_holdout"]["note"] = args.holdout_note
    if args.mix_csv:
        report["mix_recipe"] = {"mix_csv": args.mix_csv, "mix_csv_sha256": _sha256(Path(args.mix_csv))}
        if args.mix_recipe_json:
            report["mix_recipe"]["recipe_sha256"] = _sha256(Path(args.mix_recipe_json))

    artifacts = {
        "model_sha256": _sha256(model_path),
        "lab_csv_sha256": _sha256(Path(args.lab_csv)),
        "exclusions_sha256": _sha256(EXCLUSIONS_PATH),
    }
    if args.lab_extra_csv:
        artifacts["lab_extra_csv_sha256"] = _sha256(Path(args.lab_extra_csv))
    if args.office_csv:
        artifacts["office_csv_sha256"] = _sha256(Path(args.office_csv))
    if args.split_manifest:
        artifacts["split_manifest_sha256"] = _sha256(Path(args.split_manifest))
    artifacts["code_sha256"] = code_sha256()
    report["artifacts"] = artifacts

    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "ok",
        "mode": report["evaluation_mode"],
        "model_id": bundle.model_id,
        "threshold": thr,
        "micro_recall": round(report["micro_recall"], 4),
        "session_recall": round(report["session_recall"], 4),
        "families_below_floor": report["families_below_floor"],
        "lab_benign_flagged": report["lab_benign"]["flagged"],
        "office": report.get("office"),
        "metrics_pass": report["metrics_pass"],
        "production_ready": report["production_ready"],
        "report": args.out_json,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
