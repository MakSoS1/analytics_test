from __future__ import annotations

"""Correctness overlays for the Bronze/Silver/Gold pipeline."""

import json
from pathlib import Path
from typing import Any

import pandas as pd

from . import pipeline as _base

_original_assign_split = _base.assign_split
_original_leakage_audit = _base.leakage_audit
_original_build_gold = _base.build_gold


def assign_split(row: pd.Series) -> str:
    stage = str(row.get("experiment_stage", "")).lower()
    role = str(row.get("dataset_role", "")).lower()
    cid = str(row.get("campaign_id", ""))
    if role == "hard_negative" or stage == "g_trusted_background" or cid.startswith("g-"):
        return "challenge"
    return _original_assign_split(row)


def leakage_audit(df: pd.DataFrame, split_counts: dict[str, int]) -> dict[str, Any]:
    report = _original_leakage_audit(df, split_counts)
    split_series = df.apply(assign_split, axis=1)
    role = df.get("dataset_role", pd.Series([""] * len(df), index=df.index)).fillna("").astype(str).str.lower()
    stage = df.get("experiment_stage", pd.Series([""] * len(df), index=df.index)).fillna("").astype(str).str.lower()
    cid = df.get("campaign_id", pd.Series([""] * len(df), index=df.index)).fillna("").astype(str)
    hard = (role == "hard_negative") | (stage == "g_trusted_background") | cid.str.startswith("g-")
    bad = df.loc[hard & split_series.isin(["train", "validation", "test"]), "campaign_id"].astype(str).tolist()
    report["hard_negative_outside_challenge"] = bad
    report["passed"] = bool(report.get("passed", False)) and not bad
    return report


def build_gold(stage_dir: Path, silver: Path, gold: Path, pcap: Path):
    result = _original_build_gold(stage_dir, silver, gold, pcap)
    session_path = gold / "session_features.parquet"
    diagnostics = {
        "contract_revision": 2,
        "mapping_threshold": 0.95,
        "zero_packet_campaigns": [],
        "zero_packet_campaign_count": 0,
    }
    if session_path.exists():
        df = pd.read_parquet(session_path)
        if "packet_count" in df.columns:
            zero = df.loc[df.packet_count.fillna(0) <= 0, "campaign_id"].astype(str).tolist()
            diagnostics["zero_packet_campaigns"] = zero[:500]
            diagnostics["zero_packet_campaign_count"] = len(zero)
    (gold / "mapping_diagnostics.json").write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n")
    return result


# Functions in pipeline.py resolve these symbols from their module globals at
# call time, so replacing them here upgrades build_splits/leakage without
# duplicating the large normalization implementation.
_base.assign_split = assign_split
_base.leakage_audit = leakage_audit
_base.build_gold = build_gold


if __name__ == "__main__":
    _base.main()
