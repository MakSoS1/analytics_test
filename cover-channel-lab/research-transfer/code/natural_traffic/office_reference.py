"""Pinned, read-only office measurements for defender-only transfer diagnostics.

The September snapshots are not verified benign and cannot establish an FPR.
The older 23 September table is a supplementary, differently grouped view.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .office_day_transfer import TRANSPORT_FEATURES, load_additional_days


_ADDITIONAL_MANIFEST_SHA256 = "6ed3ca2683e12f09bfe61a614b12cbdb0571713d1ed4b3fc20e486a1de6ba217"
_COVER_MANIFEST_SHA256 = "881f7a83d549ac08141ea54e6f53b9a9f053b94247138beffb0e0b227b3eaa95"
_REQUIRED_DAYS = ("2026-09-22", "2026-09-28")


def _sha(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_office_reference(
    additional_days_dir: Path, office_cover_dir: Path | None = None,
) -> dict[str, pd.DataFrame]:
    """Require original snapshot manifests and data bytes before reading."""
    root = Path(additional_days_dir)
    if _sha(root / "DATA_MANIFEST.json") != _ADDITIONAL_MANIFEST_SHA256:
        raise ValueError("office additional-days manifest SHA256 mismatch")
    day22, day28 = load_additional_days(root, verify_hashes=True)
    days = {"2026-09-22": day22, "2026-09-28": day28}
    if office_cover_dir is not None:
        old = Path(office_cover_dir)
        if _sha(old / "DATA_MANIFEST.json") != _COVER_MANIFEST_SHA256:
            raise ValueError("office 23 September manifest SHA256 mismatch")
        manifest = json.loads((old / "DATA_MANIFEST.json").read_text())
        entry = next((x for x in manifest["tables"]
                      if x["file"] == "pipeline_office_full.parquet"), None)
        if not entry or entry["rows"] != 5726 or entry["columns"] != 180:
            raise ValueError("unexpected office 23 September manifest schema")
        path = old / entry["file"]
        if _sha(path) != entry["sha256"]:
            raise ValueError("office 23 September table SHA256 mismatch")
        frame = pd.read_parquet(path)
        if frame.shape != (5726, 180):
            raise ValueError("office 23 September frame shape mismatch")
        days["2026-09-23"] = frame
    return days


def freeze_feature_contract(
    corpus_X: pd.DataFrame, days: dict[str, pd.DataFrame],
) -> dict:
    """Choose measured *transport-only* schema, never based on attack scores.

    September 23 may be used as a separate diagnostic if its measured
    columns agree. It does not alter the frozen 22/28 feature set.
    """
    if any(day not in days for day in _REQUIRED_DAYS):
        raise ValueError("both predeclared office days 2026-09-22 and 2026-09-28 required")
    if corpus_X.empty or any(days[d].empty for d in _REQUIRED_DAYS):
        raise ValueError("empty measured office or corpus features")
    selected = []
    for name in TRANSPORT_FEATURES:
        frames = (corpus_X, days["2026-09-22"], days["2026-09-28"])
        if any(name not in frame.columns for frame in frames):
            continue
        numeric = [pd.to_numeric(frame[name], errors="coerce").replace(
            [np.inf, -np.inf], np.nan) for frame in frames]
        if all(float(series.notna().mean()) >= .8 for series in numeric):
            selected.append(name)
    if len(selected) < 12:
        raise ValueError("need at least 12 comparable measured transport features")
    day_status = {}
    for day, frame in days.items():
        if day in _REQUIRED_DAYS:
            day_status[day] = "reference_measured"
            continue
        comparable = all(name in frame and float(pd.to_numeric(
            frame[name], errors="coerce").replace([np.inf, -np.inf], np.nan)
            .notna().mean()) >= .8 for name in selected)
        day_status[day] = "diagnostic_comparable" if comparable else "incompatible_features"
    tls22 = days["2026-09-22"]
    unmeasured_tls = ("tls_version" not in tls22 or
                      pd.to_numeric(tls22["tls_version"], errors="coerce").notna().sum() == 0)
    schema_hash = sha256(json.dumps(selected, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "version": "defender-office-measurement-contract-v1",
        "feature_columns": selected,
        "feature_schema_sha256": schema_hash,
        "day_status": day_status,
        "unavailable_families": {
            "tls": "unmeasured_on_2026-09-22" if unmeasured_tls else "excluded_transport_only_policy",
            "dns": "excluded_transport_only_policy",
            "ssh": "excluded_transport_only_policy",
        },
        "office_labels": "unknown_unverified",
        "holdout_excluded_from_model_selection": True,
        "office_naturalness_proven": False,
        "production_ready": False,
    }
