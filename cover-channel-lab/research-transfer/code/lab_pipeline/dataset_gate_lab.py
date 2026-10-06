#!/usr/bin/env python3
"""Hard checks on lab feature CSV before any KPI claim (plan v3 §33/§42)."""
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
from lab_pipeline.train_lab_binary import MIN_TEST_NEG, MIN_TEST_POS, split_campaigns  # noqa: E402

QUARANTINE_SOURCES = {"wsl_tunnel_lab_v2"}


def gate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    overlap = sorted(set(MODEL_FEATURE_NAMES) & LEAKAGE_FEATURES)
    if overlap:
        failures.append(f"schema leakage in MODEL_FEATURE_NAMES: {overlap}")
    present_leak = sorted({c for row in rows[:1] for c in row if c in LEAKAGE_FEATURES})
    # Leakage columns may exist on the row for QC; they must not be model features.
    used_as_model = [c for c in present_leak if c in MODEL_FEATURE_NAMES]
    if used_as_model:
        failures.append(f"leakage columns used as model features: {used_as_model}")
    sources = Counter(r.get("capture_source") for r in rows)
    if any(src in QUARANTINE_SOURCES for src in sources):
        failures.append("quarantined v2 captures present; exclude wsl_tunnel_lab_v2")
    missing_feats = [n for n in MODEL_FEATURE_NAMES if rows and n not in rows[0]]
    if missing_feats:
        failures.append(f"missing model features: {missing_feats[:8]}")
    splits = split_campaigns(rows)
    n_pos = sum(1 for r in splits["test"] if str(r.get("label_binary")) == "tunnel" or str(r.get("y")) == "1")
    n_neg = sum(1 for r in splits["test"] if str(r.get("label_binary")) == "benign" or str(r.get("y")) == "0")
    kpi_ok = n_pos >= MIN_TEST_POS and n_neg >= MIN_TEST_NEG and not failures
    status = "ok" if not failures else "fail"
    if not kpi_ok and status == "ok":
        status = "wait_for_matrix"
    return {
        "status": status,
        "kpi_publishable": bool(kpi_ok and not failures),
        "failures": failures,
        "n_rows": len(rows),
        "sources": dict(sources),
        "n_train": len(splits["train"]),
        "n_val": len(splits["val"]),
        "n_test": len(splits["test"]),
        "test_pos": n_pos,
        "test_neg": n_neg,
        "label_columns_ignored": sorted(LABEL_COLUMNS),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--features-csv", default="/opt/tunnel_lab/features/lab_v3_features.csv")
    p.add_argument("--out-json", default="/opt/tunnel_lab/features/lab_v3_gate.json")
    args = p.parse_args()
    path = Path(args.features_csv)
    if not path.is_file():
        report = {"status": "missing_csv", "kpi_publishable": False, "failures": [str(path)]}
    else:
        with path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        report = gate(rows)
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "kpi_publishable", "n_rows") if k in report}))
    if report.get("status") in {"ok", "wait_for_matrix"}:
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
