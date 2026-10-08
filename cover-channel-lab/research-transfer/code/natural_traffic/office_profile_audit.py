"""Safe, read-only office measurement summaries for defensive research.

The historical office tables contain pseudonymous identity and unverified
labels. Neither is exported or used to make benign/attack assertions.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .office_day_transfer import TRANSPORT_FEATURES
from .office_reference import load_office_reference


def _group_summary(frame: pd.DataFrame) -> tuple[int | None, str]:
    for column, basis in (
        ("independent_source_group", "within_day_independent_source_group"),
        ("host_key", "within_day_host_key_only"),
    ):
        if column not in frame:
            continue
        values = frame[column].dropna().astype(str).str.strip()
        values = values[values.ne("")]
        if len(values) == len(frame):
            return int(values.nunique()), basis
    return None, "unavailable"


def _tls_coverage(frame: pd.DataFrame) -> str:
    if "tls_version" not in frame:
        return "unmeasured"
    measured = pd.to_numeric(frame["tls_version"], errors="coerce")
    measured = measured.replace([np.inf, -np.inf], np.nan).where(lambda x: x > 0)
    fraction = float(measured.notna().mean())
    if fraction == 0:
        return "unmeasured"
    return "measured" if fraction == 1 else "partially_measured"


def profile_office_reference(
    days: dict[str, pd.DataFrame], *, columns: list[str],
) -> dict[str, Any]:
    """Aggregate measured transport features independently within each day.

    A matching host pseudonym from two historical exports is not evidence of
    the same physical endpoint, so there is never a cross-day identity join.
    """
    allowed = set(TRANSPORT_FEATURES)
    if not columns or len(set(columns)) != len(columns) or any(
        name not in allowed for name in columns
    ):
        raise ValueError("columns must be distinct predeclared transport features")
    if not days or any(frame.empty for frame in days.values()):
        raise ValueError("empty office reference day")

    summary: dict[str, dict] = {}
    for day, frame in sorted(days.items()):
        measured: dict[str, float] = {}
        quantiles: dict[str, dict[str, float] | None] = {}
        for name in columns:
            if name not in frame:
                measured[name] = 0.0
                quantiles[name] = None
                continue
            raw = pd.to_numeric(frame[name], errors="coerce")
            finite = raw.replace([np.inf, -np.inf], np.nan).dropna()
            measured[name] = float(len(finite) / len(frame))
            if finite.empty:
                quantiles[name] = None
            else:
                values = np.percentile(finite.to_numpy(dtype=float), [10, 50, 90])
                quantiles[name] = {
                    key: float(value) for key, value in zip(
                        ("p10", "p50", "p90"), values,
                    )
                }
        groups, basis = _group_summary(frame)
        summary[day] = {
            "rows": int(len(frame)),
            "independent_groups": groups,
            "grouping_basis": basis,
            "comparison_scope": (
                "historical_unmatched_view" if day == "2026-09-23" else
                "pinned_web_candidate_sample" if day in ("2026-09-22", "2026-09-28")
                else "unspecified"
            ),
            "unavailable_families": {"tls": _tls_coverage(frame)},
            "measured_feature_coverage": measured,
            "robust_quantiles": quantiles,
        }
    return {
        "version": "office-measured-profile-audit-v1",
        "days": summary,
        "feature_columns": columns,
        "office_labels": "unknown_unverified",
        "cross_day_group_join_permitted": False,
        "naturalness_proven": False,
        "production_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--office-dir", required=True, type=Path)
    parser.add_argument("--office-cover-dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError(args.out)
    days = load_office_reference(args.office_dir, args.office_cover_dir)
    columns = [name for name in TRANSPORT_FEATURES if any(
        name in frame for frame in days.values()
    )]
    report = profile_office_reference(days, columns=columns)
    manifests = [args.office_dir / "DATA_MANIFEST.json"]
    if args.office_cover_dir is not None:
        manifests.append(args.office_cover_dir / "DATA_MANIFEST.json")
    report["verified_manifest_sha256"] = {
        ("additional_days" if i == 0 else "office_cover"):
            sha256(path.read_bytes()).hexdigest()
        for i, path in enumerate(manifests)
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    print("OFFICE_PROFILE_AUDIT", json.dumps({
        "days": {day: data["rows"] for day, data in report["days"].items()},
        "office_labels": report["office_labels"],
        "production_ready": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
