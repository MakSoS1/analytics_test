#!/usr/bin/env python3
"""Build the labelled mix that the precision gate is measured on.

"Precision >= 0.95 on a labelled mix" is only a measurement if the mix has a
declared recipe: which rows, what prevalence, what seed. A mix assembled after
looking at the scores is threshold shopping with extra steps.

The recipe here is fixed in code:

* rows come from the lab TEST slice only — the same deterministic
  ``build_split`` the trainer used, so nothing in the mix was trained on;
* every test-slice negative (lab benign, the hard negatives) is kept — that
  pool is the scarce resource and the whole point of the measurement;
* positives are subsampled WITHOUT replacement to reach the requested
  prevalence, with a fixed seed. If the slice has fewer positives than the
  target needs, the mix keeps them all and the recipe records the lower
  prevalence it actually achieved.

The output CSV carries the source rows verbatim (features plus y) and a
sidecar JSON binds it to the source corpus by SHA256, so a release card can
check that the mix it scores is the mix the recipe describes.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from lab_pipeline.split_manifest import (  # noqa: E402
    build_split,
    rows_for_role,
)
from lab_pipeline.train_fastv1 import ROLES, keep_scorable, load  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_mix_rows(lab_rows: list[dict[str, Any]], salt: str, prevalence: float,
                   seed: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Sample the mix from the test slice. Returns rows and the recipe record."""
    kept, _dropped = keep_scorable(lab_rows)
    lab_split = build_split(kept, "session_id", ROLES, salt=salt,
                            stratify_key="label_family")
    test_rows = rows_for_role(kept, lab_split, "test")

    pos = [r for r in test_rows if str(r.get("y")) == "1"]
    neg = [r for r in test_rows if str(r.get("y")) != "1"]
    if not pos or not neg:
        raise SystemExit(json.dumps({
            "status": "mix_slice_degenerate",
            "detail": f"test slice has {len(pos)} positive / {len(neg)} negative rows; "
                      f"a mix needs both classes",
        }))

    # Keep every negative, size the positive side to the requested prevalence.
    target_pos = int(round(prevalence / (1.0 - prevalence) * len(neg)))
    chosen = list(pos)
    if target_pos < len(pos):
        rng = random.Random(seed)
        chosen = sorted(rng.sample(pos, target_pos),
                        key=lambda r: str(r.get("flow_instance_id") or ""))
    actual = len(chosen) / (len(chosen) + len(neg))

    recipe = {
        "recipe": "all test-slice negatives + positives sampled to the requested prevalence",
        "salt": salt,
        "prevalence_requested": prevalence,
        "prevalence_actual": actual,
        "seed": seed,
        "positive_rows": len(chosen),
        "negative_rows": len(neg),
        "total_rows": len(chosen) + len(neg),
        "slice_source": "lab test slice (train/validation rows excluded by the split)",
        "lab_split_groups": lab_split["group_counts"],
    }
    return chosen + neg, recipe


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab-csv", required=True)
    ap.add_argument("--salt", default="fastv1-v1",
                    help="must match the salt the model was trained with")
    ap.add_argument("--prevalence", type=float, default=0.05,
                    help="target share of tunnel rows in the mix")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    src = Path(args.lab_csv)
    rows = load(src)
    mix, recipe = build_mix_rows(rows, args.salt, args.prevalence, args.seed)

    recipe["source_csv"] = str(src)
    recipe["source_sha256"] = _sha256(src)
    out_csv = Path(args.out_csv)
    fieldnames = list(rows[0].keys()) if rows else []
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(mix)
    recipe["mix_csv_sha256"] = _sha256(out_csv)

    Path(args.out_json).write_text(json.dumps(recipe, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: recipe[k] for k in
                      ("total_rows", "positive_rows", "negative_rows",
                       "prevalence_requested", "prevalence_actual")},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
